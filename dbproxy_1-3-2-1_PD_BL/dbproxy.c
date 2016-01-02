#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <glib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/wait.h>
#include "config.h"
#include "Epoll.h"
#include "log.h"
#include "network.h"
#include "global.h"
#include "zookeeper.h"
#include "jansson.h"

#if defined(__DATE__) && defined(__TIME__)
static const char BuildDate[] = __DATE__ " " __TIME__;
#else
static const char BuildDate[] = "unknown";
#endif
extern int init_db_user(network_server_config *config, GKeyFile *conf_file, gchar *group, int is_update);
extern int init_product_user(network_server_config *config, GKeyFile *conf_file, gchar *group, int is_update);
extern int init_auth_ip(network_server_config *config, GKeyFile *conf_file, gchar *group);
extern int init_network_database_by_group(network_server_config *config, GKeyFile *conf_file, 
		gchar *group, int is_slave, int is_read_from_local, int is_update);
extern int poll_events_add(poll *p, network_socket *s, unsigned int events);
extern inline int set_fd_flags(int fd);
extern int handshake_read(network_socket *s);
extern network_socket* server_connection_failover(network_socket *server,
		        network_socket *client);
extern int auth_send(network_server *srv, network_socket *s);
extern int poll_events_mod(poll *p, network_socket *s, unsigned int events);
extern inline int auth_result_read(network_socket *s);
extern int query_send(network_socket *s);
extern int query_result_read(network_socket *s);
extern inline int auth_read(network_socket *s, network_server *srv);
extern inline int fill_auth_failed_packet(network_socket *s, char *data, int len);
extern guint str_hash(char *v);
extern inline int auth_result_send(network_socket *s);
extern int make_last_insert_id_packet(network_socket *s, int is_execute);
extern inline int make_proxy_status_result_packet(network_socket *s, int type);
extern inline int fill_ok_packet(network_socket *s);
extern inline int query_result_send(network_socket *s);
extern int network_socket_buf_reset(network_socket *s);
extern inline void byte_array_free(byte_array *arr);
extern void log_work(t_logger *logger, network_socket *client, int type);

void process_ready_server_network_socket(network_server *srv,
        network_socket *s, poll *poll);
void process_ready_client_network_socket(network_server *srv,
        network_socket *s, poll *poll);

int pnum = 0;
network_socket *listen_socket;
network_server *srv;

void sig_25_handler(int signum){
    if(signum == 25){
        printf("\nnot enough disk space!!!\n");
        return;
    }
}


network_server* create_network_server(char *conf_path) {
    if (NULL == (srv = calloc(1, sizeof(network_server)))) {
        printf("%s:%s:%d not enough memory\n", __FILE__, __PRETTY_FUNCTION__,
                __LINE__);
        return NULL;
    }

    
    if (NULL == (srv->config = get_network_server_config(conf_path))) {
        printf("%s:%s:%d create config failed \n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return NULL;
    }

    snprintf(srv->config->conf_path, MAX_FILE_NAME_LEN,"%s", conf_path);

    if (NULL == (logger = logger_create(srv->config->log_dir,
            srv->config->log_filename, srv->config->log_maxsize,
            srv->config->log_level))) {
        printf("%s:%s:%d create logger failed \n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return NULL;
    }

	if (NULL == (srv->sockets_pool = network_socket_pool_create())) {
        printf("socket_pool create failed\n");
        return NULL;
    }
    srv->sockets_pool->srv = srv;
    
    return srv;
}

inline int check_auth(network_server *srv, struct sockaddr_in *client_addr) {

    if (NULL == client_addr)
        return -1;
    GPtrArray *auth_ips = srv->config->auth_ips;
    int i;
    for (i = 0; i < auth_ips->len; i++) {
        auth_ip *ip = g_ptr_array_index(auth_ips, i);
        if (ip->addr.s_addr == client_addr->sin_addr.s_addr) {
            return 0;
        }
    }
    return -1;
}

int check_update_info(network_server *srv){

    struct stat conf;
    if(0 != stat(srv->config->conf_path,&conf)){
        log_warning(logger,"read the status of %s failed",srv->config->conf_path);
        goto UPDATE_DB;
    }

    if(srv->config->is_autoload_enable == 1 && conf.st_mtime != srv->config->conf_modify_time){
        srv->config->conf_modify_time = conf.st_mtime;
        GKeyFile *conf_file;

        if (NULL == (conf_file = g_key_file_new())) {
            log_error(logger,"g_key_file_new() return null");
            goto UPDATE_DB;
        }
        if (0 == g_key_file_load_from_file(conf_file, srv->config->conf_path,
                0, NULL)) {
            log_error(logger,"g_key_file_load_from_file() failed conf_path=%s", srv->config->conf_path);
            g_key_file_free(conf_file);
            goto UPDATE_DB;
        }
        srv->config->user_update_flag++;
        gsize g_cnt = -1;
        gchar **groups = NULL;

        if ((NULL == (groups = g_key_file_get_groups(conf_file, &g_cnt)))
                || g_cnt <= 0) {
            log_error(logger,"config file=%s doesn't have any group", srv->config->conf_path);
            g_key_file_free(conf_file);
            goto UPDATE_DB;
        }

		while(srv->config->auth_ips->len > 0) {
			auth_ip* ip = g_ptr_array_remove_index(srv->config->auth_ips,srv->config->auth_ips->len - 1);
			if(ip != NULL) {
				free(ip);
			}
		}
        g_ptr_array_free(srv->config->auth_ips, 1);
        if (NULL == (srv->config->auth_ips = g_ptr_array_new())) {
            log_error(logger,"config->auth_ips = g_ptr_array_new() return null");
            g_key_file_free(conf_file);
            goto UPDATE_DB;
        }

        int i = 0;
        int j = 0;
        for (i = 0; i < g_cnt; i++) {
            if (NULL != strstr(groups[i], CONFIG_DBUSER_GROUP_PREFIX)) {
                if (-1 == init_db_user(srv->config, conf_file, groups[i], 1)) {
                    log_error(logger,"init_db_user failed, group=%s", groups[i]);
                    continue;
                }
            } else if (NULL != strstr(groups[i],
                    CONFIG_PRODUCTUSER_GROUP_PREFIX)) {
                if (-1 == init_product_user(srv->config, conf_file, groups[i],
                        1)) {
                    log_error(logger,"init_product_user failed, group=%s", groups[i]);
                    continue;
                }
            } else if (NULL != strstr(groups[i], CONFIG_AUTH_IP_GROUP_PREFIX)) {
                if (-1 == init_auth_ip(srv->config, conf_file, groups[i])) {
                    log_error(logger,"init_auth_ip failed, group=%s", groups[i]);
                    continue;
                }
            }
        }
        for (j = 0; j < g_cnt; j++) {
            free(groups[j]);
        }
        free(groups);
        g_key_file_free(conf_file);
        log_load(logger,"reload config group DB_User, Product_User and Auth_IP success");
    }


UPDATE_DB:

    if(srv->config->is_zk_enable == 1){

        int zk_len = srv->config->zk_path_array->len;

        int array_index = 0;
        char conf_path[MAX_FILE_NAME_LEN];
        struct stat conf_stat;
        for(array_index = 0;array_index < zk_len; array_index++){

            char *zk_path = (char*) g_ptr_array_index(srv->config->zk_path_array,array_index);

            db_group_info *bd = (db_group_info*) g_hash_table_lookup(
                    srv->config->basic_db_info, zk_path);
            snprintf(conf_path, MAX_FILE_NAME_LEN, "%s/%d.conf",
                    srv->config->zk_conf_dir, array_index);


            int conf_file_fd = open(conf_path,O_RDONLY);
            if(conf_file_fd == -1) {
                log_warning(logger,"open zk local conf file failed, file_name=%s", conf_path);
                continue;
            }

            /*int lock_ret = flock(conf_file_fd,LOCK_SH | LOCK_NB);*/
            int lock_ret = flock(conf_file_fd,LOCK_SH);
            if(lock_ret == -1) {
               log_warning(logger,"lock_sh on file %s failed!",conf_path);
               close(conf_file_fd);
               continue;
            }

            if(0 != stat(conf_path,&conf_stat)){
                log_warning(logger,"read the status of %s failed",conf_path);
                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }

            if(bd->modify_time == conf_stat.st_mtime){

                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }

            bd->modify_time = conf_stat.st_mtime;

            GKeyFile *conf_file;

            if (NULL == (conf_file = g_key_file_new())) {
                log_error(logger,"g_key_file_new() return null,array_index : %d",array_index);
                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }
            if (0 == g_key_file_load_from_file(conf_file, conf_path, 0, NULL)) {
                log_warning(logger,"g_key_file_load_from_file() failed, conf_path=%s,maybe the file is empty", conf_path);
                g_key_file_free(conf_file);
                if(bd->is_slave  == 1){
                    bd->basic_db->clus->r_update_flag++;
                } else {
                    bd->basic_db->clus->w_update_flag++;
                }
                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }

            gsize g_cnt = -1;
            gchar **groups = NULL;

            if ((NULL == (groups = g_key_file_get_groups(conf_file, &g_cnt)))
                    || g_cnt <= 0) {
                log_error(logger,"config file=%s doesn't have any group", conf_path);
                g_key_file_free(conf_file);
                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }

            int i = 0;
            int j = 0;
            int is_set_update_flag = 0;
            for (i = 0; i < g_cnt; i++) {
                if (NULL != strstr(groups[i], CONFIG_DB_MASTER_GROUP_PREFIX)) {

                    if(is_set_update_flag == 0){
                        is_set_update_flag = 1;
                        bd->basic_db->clus->w_update_flag++;
                    }

                    if (-1 == init_network_database_by_group(srv->config,
                            conf_file, groups[i], 0, 1, 1)) {
                        log_error(logger,"init_network_database_by_group failed, group=%s",
                                groups[i]);

                        continue;
                    }
                } else if (NULL != strstr(groups[i], CONFIG_DB_SLAVE_GROUP_PREFIX)) {

                    if(is_set_update_flag == 0){
                        is_set_update_flag = 1;
                        bd->basic_db->clus->r_update_flag++;
                    }
                    if (-1 == init_network_database_by_group(srv->config,
                            conf_file, groups[i], 1, 1, 1)) {
                        log_error(logger,"init_network_database_by_group failed, group=%s",
                                groups[i]);

                        continue;
                    }
                } else {
                    log_warning(logger,"group name=%s is not master or slave ",groups[i]);
                }
            }

            for (j = 0; j < g_cnt; j++) {
                free(groups[j]);
            }
            free(groups);
            g_key_file_free(conf_file);

            int k;
            for (k = 0; k <= srv->poll->max_fd; k++) {
                network_socket *cur_s;
                if (NULL == (cur_s = srv->poll->fd_mapping[k])) {
                    continue;
                }
                if(cur_s->ms == MS_MASTER){
                    if(cur_s->is_client_socket == 0 && cur_s->db != NULL && cur_s->db->is_old != cur_s->db->clus->w_update_flag
                            && cur_s->is_in_pool == 1){
                        server_free(cur_s,0);
                        cur_s = NULL;
                    }
                }else{
                    if(cur_s->is_client_socket == 0 && cur_s->db != NULL && cur_s->db->is_old != cur_s->db->clus->r_update_flag
                            && cur_s->is_in_pool == 1){
                        server_free(cur_s,0);
                        cur_s = NULL;
                    }
                }

            }
            flock(conf_file_fd,LOCK_UN);
            close(conf_file_fd);

            log_load(logger,"reload config group Mater_Host and Slave_Host success");
        }
    }
	return 0;
}

void update_proxy_status(network_server *srv){

    srv->config->mmap_flag++;
    srv->child_s4->mmap_flag = srv->config->mmap_flag;

    struct timeval time;
    gettimeofday(&time, 0);
    struct tm *tm = localtime(&(time.tv_sec));

    char cur_time[MAX_STATUS_TIME_LEN];

    snprintf(cur_time, sizeof(cur_time), "%d-%d-%d %d:%d:%d", 1900
            + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour,
            tm->tm_min, tm->tm_sec);

    GHashTable *sessions = srv->config->sessions;
    GList *session_keys = g_hash_table_get_keys(sessions);
    GList *session_head = session_keys;
    while (NULL != session_head) {
        network_socket *client = g_hash_table_lookup(sessions,
                (int*) session_head->data);

        status_user_and_ip *t1 = srv->child_s1;
        int i = 0;
        int first_not_used_index = -1;
        for (i = 0; i < srv->s1_num; i++) {
            if (t1->is_used != srv->config->mmap_flag) {
                if (first_not_used_index == -1){
                    first_not_used_index = i;
                    break;
                }
            } else {
                if (t1->key == client->key_type1) {
                    t1->proxy_connections++;

                    if (client->is_using_db == 1 && client->db != NULL) {
                        t1->db_connections++;
                        if (client->ms == MS_MASTER) {
                            if (NULL == strstr(t1->masters,
                                    client->db->addr.addr_name)) {
                                int len = strlen(t1->masters);
                                snprintf(t1->masters + len,
                                        MAX_STATUS_IPS_LEN - len, " %s ",
                                        client->db->addr.addr_name);
                            }
                        } else {
                            if (NULL == strstr(t1->slaves,
                                    client->db->addr.addr_name)) {
                                int len = strlen(t1->slaves);
                                snprintf(t1->slaves + len,
                                        MAX_STATUS_IPS_LEN - len, " %s ",
                                        client->db->addr.addr_name);
                            }
                        }
                    }
                    break;
                }
            }
            t1 += 1;
        }
        if (i == srv->s1_num || t1->is_used != srv->config->mmap_flag) {
            if (first_not_used_index != -1) {
                t1 = srv->child_s1 + first_not_used_index;
                t1->is_used = srv->config->mmap_flag;
                snprintf(t1->username_and_ip, sizeof(t1->username_and_ip),
                        client->username_and_ip);
                t1->proxy_connections = 1;
                if (client->is_using_db == 1 && client->db != NULL) {
                    t1->db_connections = 1;
                    if (client->ms == MS_MASTER) {
                        snprintf(t1->masters, MAX_STATUS_IPS_LEN, "%s ",
                                client->db->addr.addr_name);
                        t1->slaves[0] = '\0';
                    } else {
                        snprintf(t1->slaves, MAX_STATUS_IPS_LEN, "%s ",
                                client->db->addr.addr_name);
                        t1->masters[0] = '\0';
                    }
                }
                t1->key = client->key_type1;
                snprintf(t1->cur_time, sizeof(t1->cur_time),"%s", cur_time);
                snprintf(t1->pid,sizeof(t1->pid),"%s",srv->config->pid);
            } else {
                log_error(logger,"not enough memory for proxy status type1 username+ip");
            }
        }

        status_dbip_and_user *t2 = srv->child_s2;
        first_not_used_index = -1;
        for (i = 0; i < srv->s2_num; i++) {
            if (t2->is_used != srv->config->mmap_flag) {
                if (first_not_used_index == -1) {
                    first_not_used_index = i;
                    break;
                }
            } else {
                if (t2->key == client->key_type2) {
                    t2->connection_num++;
                    break;
                }
            }
            t2 += 1;
        }
        if (i == srv->s2_num || t2->is_used != srv->config->mmap_flag) {
            if (first_not_used_index != -1) {
                t2 = srv->child_s2 + first_not_used_index;
                t2->is_used = srv->config->mmap_flag;
                snprintf(t2->dbip_and_user_and_userip,
                        MAX_STATUS_TYPE_2_KEY,
                        client->dbip_and_user_and_userip);
                t2->key = client->key_type2;
                t2->connection_num = 1;
                snprintf(t2->cur_time, sizeof(t2->cur_time),"%s", cur_time);
                snprintf(t2->pid,sizeof(t2->pid),"%s",srv->config->pid);
            } else {
                log_warning(logger,"not enough memory for proxy status type2 dbip_and_user_and_userip");
            }
        }

        session_head = session_head->next;
    }
	g_list_free(session_keys);


    //////////////////////////

    char proc_path[MAX_PROC_PATH_LEN];
    snprintf(proc_path, sizeof(proc_path), "/proc/%s/status", srv->config->pid);

    FILE *proc_file = fopen(proc_path, "r");
    char vmsize[MAX_PROC_STATUS_LEN];
    if (proc_file == NULL) {
        log_error(logger,"open proc file %s failed",proc_path);
        return;
    }
    int i;
    for (i = 0; i < 11; i++) {
        if (fgets(vmsize, sizeof(vmsize), proc_file) == NULL) {
            log_error(logger,"read proc file %s failed",proc_path);
            return;
        }
    }
    if (fgets(vmsize, sizeof(vmsize), proc_file) == NULL) {
        log_error(logger,"read proc file %s failed",proc_path);
        return;
    }
    fclose(proc_file);

    status_mysql_proxy_layer *s3 = srv->child_s3;

    snprintf(s3->cur_time, sizeof(s3->cur_time), "%d-%d-%d %d:%d:%d", 1900
            + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour,
            tm->tm_min, tm->tm_sec);

    snprintf(s3->vmsize, MAX_PROC_STATUS_LEN, "%s",vmsize);
    snprintf(s3->pid,sizeof(s3->pid),"%s",srv->config->pid);
    s3->vmsize[strlen(s3->vmsize) - 1] = '\0';

    s3->network_socket_pool_num = srv->sockets_pool->sockets->length;

    int off = 0;
    char pool_stat[MAX_PROC_CONN_LEN];
    GHashTable *clusters = srv->config->clusters;
    GList *cluster_keys = g_hash_table_get_keys(clusters);
    GList *cluster_head = cluster_keys;
    while (NULL != cluster_head) {
        cluster *clus = g_hash_table_lookup(clusters,
                (char*) cluster_head->data);
        GHashTable *db_conn_pool = clus->db_conn_pools;
        GList *pool_keys = g_hash_table_get_keys(db_conn_pool);
        GList *pool_head = pool_keys;
        while (NULL != pool_head) {
            GHashTable *db_user_mapping = g_hash_table_lookup(db_conn_pool,
                    (char*) pool_head->data);
            GList *db_name_keys = g_hash_table_get_keys(db_user_mapping);
            GList *db_name_head = db_name_keys;
            while (NULL != db_name_head) {
                conn_pool_queue *queue = g_hash_table_lookup(
                        db_user_mapping, (char*) db_name_head->data);

                if (queue != NULL) {
                    snprintf(pool_stat, sizeof(pool_stat),
                            "%s@%s:Write_Queue %d\n",
                            (char*) pool_head->data,
                            (char*) db_name_head->data,
                            queue->w_queue->length);
                    snprintf(s3->conn_pool_stat + off,
                            sizeof(s3->conn_pool_stat) - off, pool_stat);
                    off += strlen(pool_stat);

                    snprintf(pool_stat, sizeof(pool_stat),
                            "%s@%s:Read_Queue %d\n",
                            (char*) pool_head->data,
                            (char*) db_name_head->data,
                            queue->r_queue->length);
                    snprintf(s3->conn_pool_stat + off,
                            sizeof(s3->conn_pool_stat) - off, pool_stat);
                    off += strlen(pool_stat);
                }
                db_name_head = db_name_head->next;
            }
			g_list_free(db_name_keys);
            pool_head = pool_head->next;
        }
		g_list_free(pool_keys);
        cluster_head = cluster_head->next;
    }
	g_list_free(cluster_keys);
}

int zk_process(int pnum, network_socket *listen_socket, network_server *srv) {

    if (NULL == (logger = logger_create(srv->config->log_dir,
            srv->config->log_filename, srv->config->log_maxsize,
            srv->config->log_level))) {
        printf("%s:%s:%d create logger failed, %s\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }

    network_server_config *config = srv->config;
    pid_t pid = getpid();

    config->zh = NULL;
    if (-1 == init_zookeeper(config, config->zk_host,
                config->zk_log,1)) {
        log_error(logger,"init_zookeeper failed, zk_host=%s, zk_log=%s", config->zk_host, config->zk_log);
		return -1;
    }


    snprintf(config->pid,sizeof(config->pid),"%d",pid);

    signal(25, sig_25_handler);

	char* db_data = NULL;

	db_data = (char*) malloc(sizeof(char)*1024*32);
	if(db_data == NULL) {
		log_error(logger,"malloc memory failed, need %d bytes, no enough memory", sizeof(char)*1024*32);
		return -1;
	}

	int zk_num = 0;
	while(1) {

        //获取间隔
        sleep(srv->config->zk_interval);

        for(zk_num = 0; zk_num < config->zk_path_array->len; zk_num++) {

            char* path = g_ptr_array_index(config->zk_path_array,zk_num);

			memset(db_data,0,1024*32);

			int db_offset = 0;	
            
            db_group_info *bd = g_hash_table_lookup(config->basic_db_info, path);
            if (bd == NULL) {
                log_error(logger,"db_goup_info for zk_path %s is NULL",path);
                continue;
            }

            network_database *basic_db = bd->basic_db;
            
            int zk_ret;
            struct String_vector child_paths;

            zk_ret = zoo_get_children(config->zh, path, 1, &child_paths);

            if (zk_ret != ZOK) {
                const char *zk_error = zerror(zk_ret);
                log_warning(logger," zk node %s error %s", path, zk_error);
				log_warning(logger,"zookeeper connection maybe disconnected,reconnect now");
				sleep(1);
				zookeeper_close(config->zh);
				config->zh = NULL;
				if (-1 == init_zookeeper(config, config->zk_host,
							config->zk_log,1)) {
					log_error(logger,"init_zookeeper failed, zk_host=%s, zk_log=%s", config->zk_host, config->zk_log);
				}
                continue;
            }

            int i;
            char *cp;
            int db_num = child_paths.count;


            char child_path[MAX_ZOOKEEPER_PATH_LEN];
            int f_len = strlen(path) + 1;
            int c_len;
            char buffer[MAX_ZOOKEEPER_PATH_LEN];
            int len = MAX_ZOOKEEPER_PATH_LEN;
            int put_ret;

			int is_error = 0;

            for (i = 0; i < db_num; i++) {

                cp = child_paths.data[i];
                c_len = strlen(cp) + 1;

                //                snprintf(child_path, MAX_ZOOKEEPER_PATH_LEN,"%s/%s", path,cp);
                snprintf(child_path, f_len,"%s", path);
                child_path[f_len - 1] = '/';
                snprintf(child_path + f_len, c_len,"%s", cp);

                memset(buffer, 0, MAX_ZOOKEEPER_PATH_LEN);
                len = MAX_ZOOKEEPER_PATH_LEN;

                zk_ret = zoo_get(config->zh, child_path, 0, buffer, &len, NULL);
                if (zk_ret != ZOK) {
                    const char *zk_error = zerror(zk_ret);
                    log_warning(logger," zk node %s error %s", child_path, zk_error);
					log_warning(logger,"zookeeper connection maybe disconnected,reconnect now");
					sleep(1);
					zookeeper_close(config->zh);
					config->zh = NULL;
					if (-1 == init_zookeeper(config, config->zk_host,
								config->zk_log,1)) {
						log_error(logger,"init_zookeeper failed, zk_host=%s, zk_log=%s", config->zk_host, config->zk_log);
					}

					is_error = 1;
					break;
				}

                json_t *root;
                json_error_t error;

                json_t *zk_host_j;
                json_t *zk_port_j;
                json_t *weight_j;
                json_t *hostname_j;

                root = json_loads(buffer, &error);
                if(root == NULL){
                    log_warning(logger,"JSON_Parse failed content %s",buffer);
					is_error = 1;
                    break;
                }

                char *zk_host;
                char *zk_port;
                char *weight;
                char *hostname;

                zk_host_j = json_object_get(root,"ip");
                if(zk_host_j == NULL || json_is_string(zk_host_j) == 0){
                    log_warning(logger,"ip is not in the json string, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                zk_host = (char*)json_string_value(zk_host_j);
                if(strlen(zk_host) == 0){
                    log_warning(logger,"ip is empty, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }

                zk_port_j = json_object_get(root,"port");
                if(zk_port_j == NULL || json_is_string(zk_port_j) == 0){
                    log_warning(logger,"port is not in the json string, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                zk_port = (char*)json_string_value(zk_port_j);
                if(strlen(zk_port) == 0){
                    log_warning(logger,"port is empty, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                weight_j = json_object_get(root,"weight");
                if(weight_j == NULL || json_is_string(weight_j) == 0){
                    log_warning(logger,"weight is not in the json string, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                weight = (char*)json_string_value(weight_j);
                if(strlen(weight) == 0){
                    log_warning(logger,"weight is empty, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                hostname_j = json_object_get(root,"hostname");
                if(hostname_j == NULL || json_is_string(hostname_j) == 0){
                    log_warning(logger,"hostname is not in the json string, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }
                hostname = (char*)json_string_value(hostname_j);
                if(strlen(hostname) == 0){
                    log_warning(logger,"hostname is empty, zk_path=%s",path);
                    json_decref(root);
					is_error = 1;
                    break;
                }

				snprintf(db_data + db_offset, 1024*32 - db_offset, "\n[%s_%d]\n",
                        basic_db->group_name, i);
				db_offset = strlen(db_data);


				snprintf(db_data + db_offset, 1024*32 - db_offset, "host=%s\n", zk_host);
				db_offset = strlen(db_data);


				snprintf(db_data + db_offset, 1024*32 - db_offset , "zk_path=%s\n", path);	
				db_offset = strlen(db_data);

				snprintf(db_data + db_offset, 1024*32 - db_offset,  "port=%s\n", zk_port);
				db_offset = strlen(db_data);

				snprintf(db_data + db_offset, 1024*32 - db_offset, "name=%s\n", hostname);
				db_offset = strlen(db_data);

				snprintf(db_data + db_offset, 1024*32 - db_offset, "cluster_name=%s\n",
                        basic_db->clus->cluster_name);
				db_offset = strlen(db_data);


				snprintf(db_data + db_offset, 1024*32 - db_offset, "max_connections=%d\n",
                        basic_db->max_connections);
				db_offset = strlen(db_data);


				snprintf(db_data + db_offset, 1024*32 - db_offset, "connect_timeout=%d\n",
                        basic_db->connect_timeout);
				db_offset = strlen(db_data);

                
				snprintf(db_data + db_offset, 1024*32 - db_offset, "time_reconnect_interval=%d\n",
                        basic_db->time_reconnect_interval); 
				db_offset = strlen(db_data);


				snprintf(db_data + db_offset, 1024*32 - db_offset, "weight=%s\n", weight);
				db_offset = strlen(db_data);

                json_decref(root);

            }
            deallocate_String_vector(&child_paths);

			if(is_error == 1) {
				log_error(logger,"can't get db info from zk path %s", path);
				continue;
			}

			FILE *local_conf_file;
            char conf_file_name[MAX_FILE_NAME_LEN];
            snprintf(conf_file_name, MAX_FILE_NAME_LEN, "%s/%d.conf",
                    config->zk_conf_dir, bd->array_index);

            int conf_file_fd = open(conf_file_name,O_RDONLY);
            if(conf_file_fd == -1) {
                log_warning(logger,"open zk local conf file failed, file_name=%s",
                        conf_file_name);
                continue;
            }

            int lock_ret = flock(conf_file_fd,LOCK_EX);
            if(lock_ret == -1) {
               log_warning(logger,"lock_ex on file %s failed!",conf_file_name);
               close(conf_file_fd);
               continue;
            }

            if (NULL == (local_conf_file = fopen(conf_file_name, "w+"))) {
                log_warning(logger,"open zk local conf file failed, file_name=%s",
                        conf_file_name);
                flock(conf_file_fd,LOCK_UN);
                close(conf_file_fd);
                continue;
            }

			put_ret = fputs(db_data, local_conf_file);
            if (put_ret == EOF) {
                log_warning(logger,"fputs failed");
            }
			
            if (EOF == fclose(local_conf_file)) {
                log_warning(logger,"fclose failed, filename=%s", conf_file_name);
				lock_ret = flock(conf_file_fd,LOCK_UN);
				if(lock_ret == -1) {
					log_warning(logger,"unlock file %s failed",conf_file_name);
				}
                close(conf_file_fd);
				continue;
			}

            lock_ret = flock(conf_file_fd,LOCK_UN);
            if(lock_ret == -1) {
               log_warning(logger,"unlock file %s failed",conf_file_name);
            }
            close(conf_file_fd);

            log_load(logger,"get the new db info from zookeeper zk_path=%s",path);
        }
    }
	
	free(db_data);

}
int child_main(int pnum, network_socket *listen_socket, network_server *srv) {


    if (NULL == (logger = logger_create(srv->config->log_dir,
            srv->config->log_filename, srv->config->log_maxsize,
            srv->config->log_level))) {
        printf("%s:%s:%d create logger failed, %s\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
	pid_t pid = getpid();
    snprintf(srv->config->pid,sizeof(srv->config->pid),"%d",pid);

    signal(25, sig_25_handler);

    srv->s1_num = CONFIG_STATUS_MAX_PRODUCTUSER_NUM * CONFIG_STATUS_MAX_IP_NUM;
    srv->child_s1 = srv->s1 + pnum * srv->s1_num;

    srv->s2_num = CONFIG_STATUS_MAX_PRODUCTUSER_NUM * CONFIG_STATUS_MAX_IP_NUM
            * CONFIG_STATUS_MAX_DB_NUM;
    srv->child_s2 = srv->s2 + pnum * srv->s2_num;

    srv->child_s3 = srv->s3 + pnum;

    srv->child_s4 = srv->s4 + pnum;
    srv->child_s4->mmap_flag = srv->config->mmap_flag;

    snprintf(srv->child_s3->vmsize, MAX_PROC_STATUS_LEN, "Vmsize:");

    int listen_fd = listen_socket->fd;
    poll *poll;
    if (NULL == (poll = poll_create())) {
        log_error(logger, "poll_create failed, process num=%d ", pnum);
        return -1;
    }
    struct epoll_event *events = poll->events;
    size_t event_size = poll->event_size;
    int epfd = poll->epfd;

    if (0 != poll_events_add(poll, listen_socket, EPOLLIN)) {
        return -1;
    }

    srv->poll = poll;
    time_t last_check_time = time(NULL);
    time_t last_update_status = time(NULL);
    time_t cur_time;
    log_load(logger, "accept process id=%d started:listen_fd=%d, listen_port=%d", pnum, listen_fd, srv->config->port);
    while (1) {
#if _BullseyeCoverage
        cov_write();
#endif

        int fd_cnt = epoll_wait(epfd, events, event_size, EPOLL_TIMEOUT);

        gettimeofday(&(srv->cur_time), 0);
        cur_time = srv->cur_time.tv_sec;

        check_update_info(srv);

        int time_pass = cur_time - last_check_time;
        int time_pass_status = cur_time - last_update_status;

        if(srv->config->proxy_status_interval > 0 && time_pass_status > srv->config->proxy_status_interval){
            update_proxy_status(srv);
            last_update_status = cur_time;
        }
        if (time_pass > srv->config->timeout_check_interval) {
            log_load(logger, "time interval=%d begin to check timeout fd, PID=%d, stats: socket_pool_count=%d",
                    time_pass, getpid(), srv->sockets_pool->sockets->length);
            last_check_time = cur_time;
            int k;

            time_t active_interval = 0;
            for (k = 0; k <= poll->max_fd; k++) {
                network_socket *s;
                if (NULL == (s = poll->fd_mapping[k])) {
                    continue;
                }

                active_interval = cur_time - s->last_active_time;

                if (s->is_client_socket == 1 && srv->config->client_timeout
                        < active_interval) {
                    log_load(logger, "client socket fd=%d timeout=%d, going to free", s->fd,
                            cur_time - s->last_active_time);
                    client_free(s, 1);
                    continue;
                }
                if (s->is_client_socket == 0 && srv->config->server_timeout
                        < (cur_time - s->last_active_time)) {
                    log_load(logger, "server socket fd=%d timeout=%d, going to free", s->fd,
                            cur_time - s->last_active_time);
                    server_free(s, 1);
                    continue;
                }
            }
        }
        int i, fd, event;
        for (i = 0; i < fd_cnt; i++) {
            event = events[i].events;
            fd = events[i].data.fd;
            if (listen_fd == fd) {
                int client_fd;
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                if (0 > (client_fd = accept(listen_fd,
                        (struct sockaddr *) &client_addr, &client_len))) {
                    continue;
                }

                int hookIndex;
                for (hookIndex = 0; hookIndex < srv->config->h_array->so_nums; hookIndex++) {

                    int ret = call_hook_func(hookIndex,0,NULL,client_fd);

                    if (ret != 0) {
                        log_warning(logger,"hook connect_server return %d",ret);
                        close(client_fd);
                        goto Label_Continue;
                    }
                }

                if (client_fd >= CONFIG_MPL_EPOLL_MAX_SIZE) {
                    log_load(logger, "client_fd=%d >= CONFIG_DBPROXY_EPOLL_MAX_SIZE=%d, going to close", client_fd, CONFIG_MPL_EPOLL_MAX_SIZE);
                    close(client_fd);
                    continue;
                }
                char *ip_address = inet_ntoa(client_addr.sin_addr);
                int is_check_ip;
                if (0 != check_auth(srv, &client_addr)) {
                    is_check_ip = 0;
                } else {
                    is_check_ip = 1;
                }

                if (0 != set_fd_flags(client_fd)) {
                    log_warning(logger, "client_fd=%d set_fd_flags error close(client)", client_fd);
                    close(client_fd);
                    continue;
                }
                network_socket *client_socket;
                if (NULL == (client_socket = network_socket_get(
                        srv->sockets_pool, 0))) {
                    log_warning(logger, "network_socket_get(sockets_pool, 0) return null client_fd=%d",
                            client_fd);
                    close(client_fd);
                    continue;
                }
                if (NULL != ip_address) {
                    if (NULL == strncpy(client_socket->ip, ip_address,20)) {
                        client_socket->ip[0] = '\0';
                        log_warning(logger, "strcpy(client_socket->ip, ip_address) failed");
                    }
                }
                client_socket->fd = client_fd;
                client_socket->state = STATE_CONNECTED_CLIENT;
                client_socket->port = ntohs(client_addr.sin_port);
                client_socket->client = client_socket;
                client_socket->server = NULL;
                client_socket->is_check_ip = is_check_ip;
                client_socket->addr = client_addr;

                poll->fd_mapping[client_socket->fd] = client_socket;
                poll_events_add(poll, client_socket, 0);
                client_socket->poll = poll;
                client_socket->srv = srv;
                fd = client_fd;
            }
            network_socket *s;
            if (NULL == (s = poll->fd_mapping[fd])) {
                log_warning(logger, "poll_get_fd_mapping(%d) return null", fd);
                //				close(fd);   // epool_delete_events(fd); could close(fd) again
                continue;
            }
            s->last_active_time = cur_time;
            if (event & EPOLLHUP || event & EPOLLERR) {
                if (s->is_client_socket == 1) {
					log_warning(logger,"EPOLL event is EPOLLHUP or EPOLLERR fd %d s->is_client_socket == 1",fd);
                    client_free(s, 1);
                } else {
					log_warning(logger,"EPOLL event is EPOLLHUP or EPOLLERR fd %d event=%d,  s->is_client_socket == 0", fd,event);
					server_free(s, 1);
                    /*
                     *log_warning(logger,"server connection failover fd %d",fd);
                     *if (s->client->is_transaction == 1 || s->client == NULL) {
                     *    server_free(s, 1);
                     *    continue;
                     *} else {
                     *    s = (network_socket*) server_connection_failover(s,
                     *            s->client);
                     *    if (s == NULL)
                     *        continue;
                     *}
                     */
                }
                continue;
            }
            if (1 == s->is_client_socket) {
                process_ready_client_network_socket(srv, s, poll);
            } else {
                process_ready_server_network_socket(srv, s, poll);
            }
            Label_Continue: continue;
        }
    }
}

void process_ready_server_network_socket(network_server *srv,
        network_socket *s, poll *poll) {

    if (NULL == s->client) {
        log_warning(logger, "db socket fd=%d s->client == NULL maybe in conn_pool and fin comes", s->fd);
        server_free(s, 0);
        return;
    }
    network_socket *client = s->client;
    int ret;
    switch (s->state) {
    case STATE_CONNECTED_SERVER: {
        int go_on = 0;
        s->is_clean = 0;
        switch (ret = handshake_read(s)) {
        case RET_SUCCESS:
            s->state = STATE_READ_HANDSHAKE;
            go_on = 1;
            break;

        case RET_WAIT_FOR_EVENT:
            break;
        case RET_HANDSHAKE_ERROR:
            log_warning(logger, "handshake_read return ret=%d s->fd=%d, s->state=%d, errno=%d, error: %s, maybe too many connection connected to db", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        case RET_SHUTDOWN:
            //获取或新建一个到数据库的连接
            s = (network_socket*) server_connection_failover(s, client);
            if (!s) {
                log_warning(logger,"can't get a new server connection");
                break;
            }
            //这里要根据status来做判断
            goto Label_Server_Failover;
        default:
            log_warning(logger, "handshake_read return ret=%d s->fd=%d, s->state=%d, errno=%d, error: %s", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        }
        if (go_on == 0)
            break;
    }
    case STATE_READ_HANDSHAKE:
        switch (ret = auth_send(srv, s)) {
        case RET_SUCCESS:
            s->state = STATE_SEND_AUTH;
            poll_events_mod(poll, s, EPOLLIN);
            break;
        case RET_WAIT_FOR_EVENT:
            poll_events_mod(poll, s, EPOLLOUT); // FIN HUP?
            break;
        case RET_SHUTDOWN:
            //获取或新建一个到数据库的连接
            s = (network_socket*) server_connection_failover(s, client);
            if (!s) {
                log_warning(logger,"can't get a new server connection");
                break;
            }
            //这里要根据status来做判断
            goto Label_Server_Failover;
        default:
            log_warning(logger, "auth_send return ret=%d s->fd=%d s->state=%d, errno=%d, error: %s", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        }
        break;
    case STATE_SEND_AUTH: {
        int go_on = 0;
        switch (ret = auth_result_read(s)) {
        case RET_SUCCESS:
            s->state = STATE_READ_AUTH_RESULT;
            s->is_clean = 1;
            go_on = 1;
            break;
        case RET_WAIT_FOR_EVENT:
            break;
        case RET_AUTH_FAILED: {
            char *username = s->p_user->d_user->username[0] == '\0' ? "NULL"
                    : s->p_user->d_user->username;
            log_warning(logger, "db proxy login mysqld use username=%s failed", username);
            server_free(s, 1);
            break;
        }
        default:
            log_warning(logger, "auth_result_read return ret=%d s->fd=%d s->state=%d, errno=%d, error: %s", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        }

        if (go_on == 0)
            break;
    }
    case STATE_READ_AUTH_RESULT: {
        if (client->query.status == QUERY_UNUSING) {
            log_warning(logger, "db socket fd=%d client->fd=%d query is null maybe wait for client and fin/rset comes", s->fd, client->fd);
            s = (network_socket*) server_connection_failover(s, client);
            if (!s) {
                log_warning(logger,"can't get a new server connection");
                break;
            }
            log_load(logger,"get new server connection");
            client->query.status = QUERY_SERVER_RESTART;

            break;
        }
        if (client->query.status == QUERY_SERVER_RESTART) {
            log_load(logger,"get new server connection done");
            client->query.status = QUERY_UNUSING;
            break;
        }
        s->is_clean = 0;
        ret = query_send(s);
        switch (ret) {
        case RET_SUCCESS:
        	gettimeofday(&(s->client->query.query_sent_time), 0);
        	/*if (0 == is_need_response(&(client->query))) {*/
            if (0 == is_need_response(client)) {

                s->state = STATE_READ_AUTH_RESULT;
                s->is_clean = 1;
                client->state = STATE_SEND_AUTH_RESULT;
                client->query.status = QUERY_UNUSING;
                bzero(&(s->result), sizeof(s->result));
                poll_events_mod(poll, client, EPOLLIN);
                break;
            }

            if (client->query.is_designated_db == 1
                    && client->is_sending_cache_cmds == 0) {
                s->state = STATE_READ_AUTH_RESULT;
                s->is_clean = 1;
                client->state = STATE_READ_QUERY_RESULT;
                poll_events_mod(poll, client, EPOLLOUT);
                client->query.is_designated_db = 0;
                process_ready_client_network_socket(srv, s->client, poll);
                break;
            }

            s->state = STATE_SEND_QUERY;
            poll_events_mod(poll, s, EPOLLIN);
            break;
        case RET_WAIT_FOR_EVENT:
            poll_events_mod(poll, s, EPOLLOUT);
            break;
        default:
            log_warning(logger, "query_send return ret=%d s->fd=%d s->state=%d, errno=%d, error: %s", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        }
        break;
    }
    case STATE_SEND_QUERY: {
        ret = query_result_read(s);
        int hookIndex;
        switch (ret) {
        case RET_SUCCESS:
        	gettimeofday(&(s->client->query.result_read_time), 0);
        	//log_debug(logger,"STATE_SEND_QUERY");
            for (hookIndex = 0; hookIndex < srv->config->h_array->so_nums; hookIndex++) {
                int ret = call_hook_func(hookIndex,3,&s,-1);
                if (ret == 0) {
                    continue;
                } else if (ret == 1) {
                    return;
                } else {
                    log_warning(logger,"query_result_read hook error");
                }
            }
            s->state = STATE_READ_AUTH_RESULT;
            s->is_clean = 1;
            s->client->state = STATE_READ_QUERY_RESULT;
            process_ready_client_network_socket(srv, s->client, poll);
            break;
        case RET_WAIT_FOR_EVENT:
            break;
        
        default:
            log_warning(logger, "query_result_read return ret=%d s->fd=%d s->state=%d, errno=%d, error: %s", ret, s->fd, s->state, errno, strerror(errno));
            server_free(s, 1);
            break;
        }
		break;
    }
	default:{
		log_warning(logger, "Unexpected state: %d", s->state);
		break;
	}
    }

    return;

    Label_Server_Failover: process_ready_server_network_socket(srv, s, poll);
}
void process_ready_client_network_socket(network_server *srv,
        network_socket *s, poll *poll) {
    int ret;
    switch (s->state) {
    case STATE_CONNECTED_CLIENT:
        switch (ret = handshake_send(s)) {
        case RET_SUCCESS:
            s->state = STATE_SEND_HANDSHAKE;
            poll_events_mod(poll, s, EPOLLIN);
            break;
        case RET_WAIT_FOR_EVENT:
            poll_events_mod(poll, s, EPOLLOUT);
            break;
        default:
            log_warning(logger, "handshake_send return error default client_fd=%d, state=%d,ret=%d, errno=%d, error: %s", s->fd, s->state,ret, errno, strerror(errno));
            client_free(s, 0);
            break;
        }
        break;
    case STATE_SEND_HANDSHAKE: {
        int go_on = 0;
        switch (ret = auth_read(s, srv)) {
        case RET_SUCCESS:
            //在这里检查业务端用户连接数
            if (s->p_user->current_connections >= s->p_user->max_connections) {

                char message[256];
                snprintf(message,256,"Username %s with %d connections has reach the max connection limit(%d)",s->p_user->username,
                        s->p_user->current_connections,s->p_user->max_connections);

                if (RET_SUCCESS != (ret = fill_auth_failed_packet(s, message,
                                strlen(message)))) {
                    log_error(logger,"fill auth failed packet failed, message=%s", message);
                    client_free(s, 0);
                    break;
                }
                gettimeofday(&(s->query.start_time), 0);
                s->query.query_sent_time = s->query.result_read_time = s->query.start_time;	//避免不跟mysql交互造成这两个变量没有赋值
                s->state = STATE_READ_QUERY_RESULT;
                s->is_auth_failed = 2;
                process_ready_client_network_socket(srv, s, srv->poll);
                break;
            }
            s->p_user->current_connections++;
            s->is_authed = 1;
            s->state = STATE_READ_AUTH;
            go_on = 1;

            //在这里初始化共享内存的结构
            snprintf(s->username_and_ip, MAX_STATUS_TYPE_1_KEY, "%s#%s",
                    s->p_user->username, s->ip);
            s->key_type1 = str_hash(s->username_and_ip);
            char session_key[30];
            snprintf(session_key, 30, "%s:%d", s->ip, s->port);
            s->session_key = g_str_hash(session_key);
            g_hash_table_insert(srv->config->sessions, &(s->session_key), s);

            break;
        case RET_WAIT_FOR_EVENT:
            break;
        case RET_AUTH_FAILED: {
            char *message = "Auth failed, please check your username & password.";
            if (RET_SUCCESS != (ret = fill_auth_failed_packet(s, message,
                    strlen(message)))) {
                log_error(logger,"fill auth failed packet failed, message=%s", message);
                client_free(s, 0);
                break;
            }
            gettimeofday(&(s->query.start_time), 0);
            s->query.query_sent_time = s->query.result_read_time = s->query.start_time;
            s->state = STATE_READ_QUERY_RESULT;
            s->is_auth_failed = 2;
            process_ready_client_network_socket(srv, s, srv->poll);
            break;
        }
        default:
            log_warning(logger, "auth_read return error default client_fd=%d,state=%d ret=%d, errno=%d, error: %s", s->fd, s->state, ret, errno, strerror(errno));
            client_free(s, 0);
            break;
        }
        //这里如果读取身份验证信息成功之后，会接着执行下一步
        if (go_on == 0)
            break;
    }
    case STATE_READ_AUTH: {
        switch (ret = auth_result_send(s)) {
        case RET_SUCCESS:
            s->state = STATE_SEND_AUTH_RESULT;
            poll_events_mod(poll, s, EPOLLIN);
			log_work(logger, s, LOG_WORK_TYPE_CONN);
            break;
        case RET_WAIT_FOR_EVENT:
            poll_events_mod(poll, s, EPOLLOUT);
            break;
        default:
            log_warning(logger, "auth_result_send return error default client_fd=%d, state=%d ret=%d,errno=%d, error: %s", s->fd, s->state, ret, errno, strerror(errno));
            client_free(s, 0);
            break;
        }
        break;
    }
    case STATE_SEND_AUTH_RESULT: {
        switch (ret = query_read(s, srv)) {
        case RET_SUCCESS: {
            gettimeofday(&(s->query.start_time), 0);
            s->query.query_sent_time = s->query.result_read_time = s->query.start_time;
            if((s->query.is_last_insert_id == 1 && s->query.command == '\x03') ||
					s->is_execute_last_insert_id == 1){

				int make_ret = 0;
				if(s->is_execute_last_insert_id == 1) {
					make_ret = make_last_insert_id_packet(s,1);
				} else {
					make_ret = make_last_insert_id_packet(s,0);
				} 

				if(make_ret == -1) {
					log_warning(logger,"can't make last insert id packet");
					if(s->server == NULL) {
						client_free(s, 0);
					} else {
						client_free(s, 1);
					}
				}

				s->state = STATE_READ_QUERY_RESULT;
                poll_events_mod(poll, s, EPOLLOUT);
                break;
			}

            if (s->query.is_proxy_status == 1) {
                if (s->query.status_type == 1) {
                    make_proxy_status_result_packet(s, 1);
                } else if (s->query.status_type == 2) {
                    make_proxy_status_result_packet(s, 2);
                } else if (s->query.status_type == 3) {
                    make_proxy_status_result_packet(s, 3);
                }
                s->state = STATE_READ_QUERY_RESULT;
                poll_events_mod(poll, s, EPOLLOUT);
                break;
            }
/*

            guint dbkey;
            if (s->is_using_db == 1) {
                dbkey = s->db->key;
            }
*/

            int is_design = s->query.is_designated_db;

            network_socket *server;
            if (NULL != (server = network_socket_get_db_socket(srv, s, poll))) {
                
				server->client_found_rows = s->client_found_rows;
				server->client_ignore_space = s->client_ignore_space;

				if (s->is_using_db == 0) {
                    s->is_using_db = 1;
                    s->p_user->d_user->current_connections++;
                }

                if (is_design == 1 && s->query.is_designated_db == 0) {
                    fill_ok_packet(s);
                    s->state = STATE_READ_QUERY_RESULT;
                    poll_events_mod(poll, s, EPOLLOUT);
                    break;
                }
                s->state = STATE_READ_QUERY;

                //这里将客户端连接的epoll事件设置为0
                poll_events_mod(poll, s, 0);

                //在这里处理use命令以及穿透需求，需要将缓存的命令发送给新的数据库
                if (s->is_exec_last_use_query == 1 || s->query.is_designated_db
                        == 1) {
                    if (s->cache_cmds->len > 0) {
                        s->is_sending_cache_cmds = 1;
                    } else {
                        s->is_exec_last_use_query = 0;
                        s->is_sending_cache_cmds = 0;
                    }

                }
                if (server->state != STATE_CONNECTED_SERVER) {
                    process_ready_server_network_socket(srv, server, poll);
                }
            } else {
                connect_db_error_send(s);
                if (s->server != NULL) {
                    client_free(s, 1);
                } else {
                    client_free(s, 0);
                }
            }
            break;
        }
        case RET_WAIT_FOR_EVENT:
            break;
        case RET_COMMAND_SHUTDOWN:
            client_free(s, 1);
            break;
        case RET_SHUTDOWN:
            client_free(s, 1);
            break;
        case RET_REAL_WRITE:
            gettimeofday(&(s->query.start_time), 0);
            s->query.query_sent_time = s->query.result_read_time = s->query.start_time;
            s->state = STATE_READ_QUERY_RESULT;
            process_ready_client_network_socket(srv, s, srv->poll);
            break;
        default:
            log_warning(logger, "query read return error default client_fd=%d, state=%d, ret=%d, errno=%d, error: %s", s->fd, s->state, ret, errno, strerror(errno));
            client_free(s, 1);
            break;
        }
        break;
    }
    case STATE_READ_QUERY_RESULT: {
        switch (ret = query_result_send(s)) {
        case RET_SUCCESS:
            if(s->is_auth_failed == 2){
                client_free(s,1);
                break;
            }

			if(s->query.is_last_insert_id == 1 && s->query.command == '\x03') {
				s->query.is_last_insert_id = 0;
			}

			if(s->is_execute_last_insert_id == 1) {
				s->is_execute_last_insert_id = 0;
			}

            if (s->query.is_proxy_status == 1) {
                s->query.is_proxy_status = 0;
            }

			gettimeofday(&(s->query.end_time), 0);
			long total_cost_us = (s->query.end_time.tv_sec - s->query.start_time.tv_sec) * 1000000
				+ s->query.end_time.tv_usec - s->query.start_time.tv_usec;
			if (total_cost_us >= srv->config->log_query_min_time) {
					log_work(logger, s, LOG_WORK_TYPE_QURY);
			}

			network_socket_buf_reset(s);

			s->query_processed_num++;

			if(s->query_processed_num >= s->srv->config->max_query_num || s->send_buf->capacity >= s->srv->config->max_query_size
					|| s->self_buf->capacity >= s->srv->config->max_query_size) {

				if(s->query_processed_num >= s->srv->config->max_query_num) {
					s->query_processed_num = 0;
				}

				if (NULL != s->self_buf)
					byte_array_free(s->self_buf);
				if (NULL != s->send_buf)
					byte_array_free(s->send_buf);
				if (s->query.args_calloc_len > 0){
					if(s->query.args != NULL) {
						free(s->query.args);
						s->query.args = NULL;
					}
					s->query.args_calloc_len = 0;
				}

				s->send_buf	= byte_array_sized_new(SEND_BUF_DEFAULT_SIZE);
				s->self_buf = byte_array_sized_new(SELF_BUF_DEFAULT_SIZE);

				if(s->send_buf == NULL || s->self_buf == NULL) {
					client_free(s,1);
					break;
				}

				if(s->server != NULL) {
					network_socket_buf_reset(s->server);
					if (NULL != s->server->self_buf)
						byte_array_free(s->server->self_buf);
					if (NULL != s->server->send_buf)
						byte_array_free(s->server->send_buf);
					if (s->server->query.args_calloc_len > 0){
						if(s->server->query.args != NULL) {
							free(s->server->query.args);
							s->server->query.args = NULL;
						}
						s->server->query.args_calloc_len = 0;
					}

					s->server->send_buf	= byte_array_sized_new(SEND_BUF_DEFAULT_SIZE);
					s->server->self_buf = byte_array_sized_new(SELF_BUF_DEFAULT_SIZE);

					if(s->server->send_buf == NULL || s->server->self_buf == NULL) {
						client_free(s,1);
						break;
					}
				}
			}
			
			s->query.status = QUERY_UNUSING;
			s->state = STATE_SEND_AUTH_RESULT;
			poll_events_mod(poll, s, EPOLLIN);
			break;
        case RET_WAIT_FOR_EVENT:
            poll_events_mod(poll, s, EPOLLOUT);
            break;
        case RET_LAST_USE_SUCCESS:
            s->state = STATE_READ_QUERY;
            poll_events_mod(poll, s, 0);
            process_ready_server_network_socket(srv, s->server, poll);
            break;
        default:
            log_warning(logger, "query_result_send return error default client_fd=%d, state=%d, ret=%d, errno=%d, error: %s", s->fd, s->state, ret, errno, strerror(errno));
            client_free(s, 1);
            break;
        }
        break;
    }
	default:{
		log_warning(logger, "Unexpected state: %d", s->state);
		break;
	}
    }
}

void init_signal_handlers() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
}

pid_t child_make(int pnum, network_socket *listen_socket, network_server *srv,int is_zoo) {
    pid_t pid;
    if (0 < (pid = fork())) {
        return pid;
    }
    if(is_zoo == 0){
        child_main(pnum, listen_socket, srv);
    } else {
        zk_process(pnum, listen_socket, srv);
    }
	return 0;
}

int network_server_start(network_server *srv) {

    if (NULL == srv) {
        log_error(logger, "start network server failed, srv==null");
        return -1;
    }

    if (NULL == (listen_socket = create_listen_network_socket(srv))) {
        log_error(logger, "create_listen_network_socket(srv) failed, errno=%d, error:%s", errno, strerror(errno));
        return -1;
    }

    srv->s1 = (status_user_and_ip*) mmap(NULL, sizeof(status_user_and_ip)
            * CONFIG_STATUS_MAX_PRODUCTUSER_NUM * CONFIG_STATUS_MAX_IP_NUM
            * srv->config->max_threads, PROT_READ | PROT_WRITE, MAP_SHARED
            | MAP_ANONYMOUS, -1, 0);

    srv->s2 = (status_dbip_and_user*) mmap(NULL, sizeof(status_dbip_and_user)
            * CONFIG_STATUS_MAX_PRODUCTUSER_NUM * CONFIG_STATUS_MAX_IP_NUM
            * CONFIG_STATUS_MAX_DB_NUM * srv->config->max_threads, PROT_READ
            | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    srv->s3 = (status_mysql_proxy_layer*) mmap(NULL,
            sizeof(status_mysql_proxy_layer) * srv->config->max_threads,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    srv->s4 = (status_mmap_flag*) mmap(NULL,
            sizeof(status_mmap_flag) * srv->config->max_threads,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

//    logger_close(logger);
//    logger = NULL;

    pid_t pids[srv->config->max_threads + 1];
    for (pnum = 0; pnum < srv->config->max_threads + 1; pnum++) {
        pids[pnum] = -1;
    }
    pid_t child_pid;
    for (pnum = 0; pnum < srv->config->max_threads; pnum++) {
        child_pid = child_make(pnum, listen_socket, srv,0);
        pids[pnum] = child_pid;
//        g_array_append_val(srv->config->pid_array,child_pid);

    }

    if(srv->config->is_zk_enable == 1) {
        child_pid = child_make(pnum, listen_socket, srv,1);
        pids[pnum] = child_pid;
    }

    zookeeper_close(srv->config->zh);
    srv->config->zh = NULL;

    pid_t epid;
    int i;
    wait_step: epid = wait(NULL);

    for (i = 0; i < srv->config->max_threads + 1; i++) {
        if (epid == pids[i]) {
            break;
        }
    }
    if (i > srv->config->max_threads) {
        log_error(logger,"dead process %d not found in pids array",epid);
    } else if(i == srv->config->max_threads && srv->config->is_zk_enable == 1){
        child_pid = child_make(i, listen_socket, srv,1);
        pids[i] = child_pid;
    } else {
        child_pid = child_make(i, listen_socket, srv,0);
        pids[i] = child_pid;
    }
   /*
    pid_t temp_pid;
    for (j = 0; j < srv->config->pid_array->len; j++) {
        temp_pid = g_array_index(srv->config->pid_array,pid_t,j);
        if (temp_pid == epid) {
            g_array_remove_index(srv->config->pid_array, j);
            break;
        }
    }
    g_array_append_val(srv->config->pid_array,child_pid);
   */
    goto wait_step;
    return 0;
}

int main(int argc, char *argv[]) {

	int c;

	while((c=getopt(argc, argv, "k:d:f:hv")) != -1) {
		switch(c) {
			case 'v':
				printf("Description: dbproxy\n");
				printf("Version    : %s\n", VERSION);
				printf("BuildDate  : %s\n", BuildDate);
				exit(-1);
			default:
				break;
		}
	}

    if (argc < 2) {
        printf("Usage: ./dbproxy confpath\n");
        exit(0);
    }
    network_server *srv;
    if (NULL == (srv = create_network_server(argv[1]))) {
        printf("create_network_server(%s) error\n", argv[1]);
        exit(0);
    }
    init_signal_handlers();
    if (0 > network_server_start(srv)) {
        printf("network_server_start() error\n");
    }

    printf("mission end\n");
	return 0;
}
