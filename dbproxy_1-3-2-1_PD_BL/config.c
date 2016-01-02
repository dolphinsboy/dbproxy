#include <pthread.h>
#include <glib.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "config.h"
#include "network.h"
#include "zookeeper.h"
#include "jansson.h"

extern guint str_hash(char *v);
extern void scramble(char *to, const char *message, const char *password);
extern inline int my_strncasestr(unsigned char *str1, unsigned char *str2, int len1,
		        int len2, int ignore_case);
extern conn_pool_queue* conn_pool_queue_create();
extern inline cluster* cluster_create();

int is_port_valid(int port) {
    return (port > 0 && port < 65535) ? 1 : 0;
}

int is_valid_str(char *str) {
    if (NULL == str || strlen(str) <= 0)
        return -1;
    return 1;
}

int set_db_address_from_zk(zhandle_t *zh, char *path, network_database *db,
        int watch) {

    if (zh == NULL) {
        printf("%s:%s:%d zh NULL\n", __FILE__, __PRETTY_FUNCTION__, __LINE__);
        return -1;
    }
    int zk_ret;
    char buffer[MAX_ZOOKEEPER_PATH_LEN];
    memset(buffer, 0, MAX_ZOOKEEPER_PATH_LEN);
    int len = MAX_ZOOKEEPER_PATH_LEN;

    zk_ret = zoo_get(zh, path, watch, buffer, &len, NULL);
    if (zk_ret != ZOK) {
        const char *zk_error = zerror(zk_ret);
        printf("%s:%s:%d zk node %s error %s\n", __FILE__, __PRETTY_FUNCTION__,
                __LINE__, path, zk_error);
        return -1;
    }
    
    json_t *root;
    json_error_t error;

    json_t *zk_host_j;
    json_t *zk_port_j;
    json_t *weight_j;
    json_t *hostname_j;

    root = json_loads(buffer, &error);
    if(root == NULL){
        printf("%s:%s:%d JSON_Parse failed \n", __FILE__, __PRETTY_FUNCTION__,
                __LINE__);
        return -1;
    }


    char *zk_host;
    char *zk_port;
    char *weight;
    char *hostname;

    zk_host_j = json_object_get(root,"ip");
    if(zk_host_j == NULL || json_is_string(zk_host_j) == 0){
        printf("ip is not in the json string, zk_path=%s\n",path);
        return -1;
    }
    zk_host = (char*)json_string_value(zk_host_j);
    if(strlen(zk_host) == 0){
        printf("ip is empty, zk_path=%s\n",path);
        return -1;
    }

    zk_port_j = json_object_get(root,"port");
    if(zk_port_j == NULL || json_is_string(zk_port_j) == 0){
        printf("port is not in the json string, zk_path=%s\n",path);
        return -1;
    }
    zk_port = (char*)json_string_value(zk_port_j);
    if(strlen(zk_port) == 0){
        printf("port is empty, zk_path=%s\n",path);
        return -1;
    }
    weight_j = json_object_get(root,"weight");
    if(weight_j == NULL || json_is_string(weight_j) == 0){
        printf("weight is not in the json string, zk_path=%s\n",path);
        return -1;
    }
    weight = (char*)json_string_value(weight_j);
    if(strlen(weight) == 0){
        printf("weight is empty, zk_path=%s\n",path);
        return -1;
    }
    hostname_j = json_object_get(root,"hostname");
    if(hostname_j == NULL || json_is_string(hostname_j) == 0 ){
        printf("hostname is not in the json string, zk_path=%s\n",path);
        return -1;
    }
    hostname = (char*)json_string_value(hostname_j);
    if(strlen(hostname) == 0){
        printf("hostname is empty, zk_path=%s\n",path);
        return -1;
    }

	snprintf(db->addr.addr_name, MAX_IP_LEN,"%s", zk_host);
    db->addr.addr_len = sizeof(db->addr.addr_ip);
    db->addr.addr_ip.sin_family = AF_INET;
    if (0 == inet_aton(zk_host, &(db->addr.addr_ip.sin_addr))) {
        printf("%s:%s:%d %s is not a valid ip\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, zk_host);
        return -1;
    }


    db->addr.port = strtoul(zk_port, NULL, 10);
    if (0 == is_port_valid(db->addr.port)) {
        printf("%s:%s:%d port=%d should in the range of [1, 65535)\n",
                __FILE__, __PRETTY_FUNCTION__, __LINE__, db->addr.port);
        return -1;
    }
    db->addr.addr_ip.sin_port = htons(db->addr.port);

    if (0 > (db->weight = strtoul(weight, NULL, 10))) {
        printf("%s:%s:%d weight=%d should > 0\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, db->weight);
        return -1;
    }

    snprintf(db->host_name, MAX_HOST_NAME_LEN,"%s", hostname);

    db->key = str_hash(zk_host);
    json_decref(root);
    return 0;
}


int init_auth_ip(network_server_config *config, GKeyFile *conf_file,
        gchar *group) {

    GError *error = NULL;
    gchar **keys = NULL;
    gchar *value = NULL;

    auth_ip *ip;
    if (NULL == (ip = calloc(1, sizeof(auth_ip)))) {
        printf("calloc(1, sizeof(auth_ip)) failed\n");
        return -1;
    }
    gsize k_cnt;
    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("group=%s doesn't have any key\n", group);
		free(ip);
        return -1;
    }
    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_AUTH_IP_IP, keys[j], strlen(
                CONFIG_AUTH_IP_IP))) {
            if (0 == inet_aton(value, &(ip->addr))) {
                printf("group=%s, key=%s , value=%s config error\n", group,
                        keys[j], value);
				free(value);
				goto error;
            }
        }
        free(value);
    }
    g_ptr_array_add(config->auth_ips, ip);
    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return 0;

error:
	free(ip);
    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return -1;
}
int init_product_user(network_server_config *config, GKeyFile *conf_file,
        gchar *group, int is_update) {

    GError *error = NULL;
    gchar **keys = NULL;
    gchar *value = NULL;

    product_user *user;
    db_user *d_user;

    if (NULL == (user = calloc(1, sizeof(product_user)))) {
        printf("calloc(1, sizeof(db_user)) failed\n");
        return -1;
    }

    user->auth_ips = g_ptr_array_new();

    if (user->auth_ips == NULL) {
        printf("%s:%s:%d user->auth_ips g_ptr_array_new failed\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
		free(user);
        return -1;
    }

    gsize k_cnt;
    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("group=%s doesn't have any key\n", group);
		free(user);
        return -1;
    }

    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_PRODUCTUSER_USERNAME, keys[j], strlen(
                CONFIG_PRODUCTUSER_USERNAME))) {
            if (strlen(value) >= MAX_USERNAME_LEN) {
                printf(
                        "group=%s, key=%s, value=%s username strlen >= MAX_USERNAME_LEN=%d\n",
                        group, keys[j], value, MAX_USERNAME_LEN);
				free(value);
				goto error;
            }
            if (NULL == strncpy(user->username, value,MAX_USERNAME_LEN)) {
                printf("strcpy value to user->username failed\n");
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_PRODUCTUSER_PASSWORD, keys[j],
                strlen(CONFIG_PRODUCTUSER_PASSWORD))) {
            if (strlen(value) >= MAX_PASSWORD_LEN) {
                printf(
                        "group=%s, key=%s, value=%s password strlen >= MAX_PASSWORD_LEN=%d\n",
                        group, keys[j], value, MAX_PASSWORD_LEN);
				free(value);
				goto error;
            }
            if (NULL == strncpy(user->password, value,MAX_PASSWORD_LEN)) {
                printf("strcpy value to user->password failed\n");
				free(value);
				goto error;
            }
            if (strcasecmp(value, "") == 0) {
                user->scramble_len = 1;
                *(user->scramble_password) = '\x00';
            } else {
                user->scramble_len = 21;
                *(user->scramble_password) = '\x14';
                scramble(
                        user->scramble_password + 1,
                        "\x2f\x55\x3e\x74\x50\x72\x6d\x4b\x56\x4c\x57\x54\x7c\x34\x2f\x2e\x37\x6b\x37\x6e",
                        user->password);
            }
        } else if (0 == strncasecmp(CONFIG_PRODUCTUSER_DB_USERNAME, keys[j],
                strlen(CONFIG_PRODUCTUSER_DB_USERNAME))) {
            if (strlen(value) >= MAX_USERNAME_LEN) {
                printf(
                        "group=%s, key=%s, value=%s db_username strlen >= MAX_USERNAME_LEN=%d\n",
                        group, keys[j], value, MAX_USERNAME_LEN);
				free(value);
				goto error;
            }
            char d_user_name[MAX_USERNAME_LEN];
            if (NULL == strncpy(d_user_name, value,MAX_USERNAME_LEN)) {
                printf("strcpy value to d_user_name failed\n");
				free(value);
				goto error;
            }
            d_user_name[strlen(value) + 1] = '\0';
            d_user = g_hash_table_lookup(config->db_user, d_user_name);
            if (d_user == NULL) {
                printf("init_product_user  d_user NULL");
				free(value);
				goto error;
            }
            if(d_user->is_old != config->user_update_flag){
                printf("the associated db_user is old\n");
				free(value);
				goto error;
            }
            user->d_user = d_user;
        } else if (0 == strncasecmp(CONFIG_PRODUCTUSER_MAX_CONNECTIONS,
                keys[j], strlen(CONFIG_PRODUCTUSER_MAX_CONNECTIONS))) {
            if (0 >= (user->max_connections = strtoul(value, NULL, 10))) {
                printf("%s:max_connections=%d should > 0\n", group,
                        user->max_connections);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_PRODUCTUSER_AUTH_IP_PREFIX, keys[j],
                6)) {
            auth_ip *ip = NULL;
            if (NULL == (ip = calloc(1, sizeof(auth_ip)))) {
                printf("%s:%s:%d calloc(1, sizeof(auth_ip)) failed\n",
                        __FILE__, __PRETTY_FUNCTION__, __LINE__);
				free(value);
				goto error;
            }
            if (0 == inet_aton(value, &(ip->addr))) {
                printf("%s:%s:%d group=%s, key=%s , value=%s config error\n",
                        __FILE__, __PRETTY_FUNCTION__, __LINE__, group,
                        keys[j], value);
				free(value);
				goto error;
            }
            g_ptr_array_add(user->auth_ips, ip);
        }

        free(value);
    }

    if (0 > is_valid_str(user->username)) {
        printf("config username is not valid\n");
		goto error;
    }
    
    product_user *u;
    if (is_update == 1 && NULL != (u = g_hash_table_lookup(config->users,
            user->username))) {
        //检查对应的数据库用户名是否改变
        if(u->d_user == NULL){
            u->d_user = user->d_user;
        } else if (my_strncasestr(u->d_user->username, user->d_user->username,
                MAX_USERNAME_LEN, MAX_USERNAME_LEN, 1) != 1) {
            u->d_user->current_connections--;
            user->d_user->current_connections++;
            u->d_user = user->d_user;
        }

        if(my_strncasestr(u->password,user->password,MAX_PASSWORD_LEN,MAX_PASSWORD_LEN,1) != 1){
            snprintf(u->password,MAX_PASSWORD_LEN,"%s",user->password);
            if (strcasecmp(u->password, "") == 0) {
                u->scramble_len = 1;
                *(u->scramble_password) = '\x00';
            } else {
                u->scramble_len = 21;
                *(u->scramble_password) = '\x14';
                scramble(
                        u->scramble_password + 1,
                        "\x2f\x55\x3e\x74\x50\x72\x6d\x4b\x56\x4c\x57\x54\x7c\x34\x2f\x2e\x37\x6b\x37\x6e",
                        u->password);
            }
        }

		while(u->auth_ips->len > 0) {
			auth_ip* ip = g_ptr_array_remove_index(u->auth_ips,u->auth_ips->len - 1);
			if(ip != NULL) {
				free(ip);
			}
		}
        g_ptr_array_free(u->auth_ips, 1);
        u->auth_ips = user->auth_ips;
        user->auth_ips = NULL;

        u->is_old = config->user_update_flag;
        free(user);
        user = NULL;
		for(j = 0; j < k_cnt; j++){
			free(keys[j]);
		}
		free(keys);
		return 0;
	}
	user->is_old = config->user_update_flag;
    g_hash_table_insert(config->users, user->username, user);

    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return 0;

error:
	free(user);
    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return -1;

}
int init_db_user(network_server_config *config, GKeyFile *conf_file,
        gchar *group, int is_update) {

    GError *error = NULL;
    gchar **keys = NULL;
    gchar *value = NULL;

    db_user *user;

    if (NULL == (user = calloc(1, sizeof(db_user)))) {
        printf("calloc(1, sizeof(db_user)) failed\n");
        return -1;
    }

	/* 默认字符编码是gbk_chinses_ci (28) */
	user->default_charset = 28;

    gsize k_cnt;
    gchar cluster_name[MAX_CLUSTER_NAME_LEN];

    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("group=%s doesn't have any key\n", group);
		free(user);
        return -1;
    }

    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_DBUSER_NAME, keys[j], strlen(
                CONFIG_DBUSER_NAME))) {
            if (strlen(value) >= MAX_USERNAME_LEN) {
                printf(
                        "group=%s, key=%s, value=%s db_user_name strlen >= MAX_USERNAME_LEN=%d\n",
                        group, keys[j], value, MAX_USERNAME_LEN);
				free(value);
				goto error;
            }
            if (NULL == strncpy(user->username, value,MAX_USERNAME_LEN)) {
                printf("strcpy value to user->db_username failed\n");
				free(value);
				goto error;
            }

        } else if (0 == strncasecmp(CONFIG_DBUSER_PASSWORD, keys[j], strlen(
                CONFIG_DBUSER_PASSWORD))) {
            if (strlen(value) >= MAX_PASSWORD_LEN) {
                printf(
                        "%s:%s:%d group=%s, key=%s, value=%s password strlen >= MAX_PASSWORD_LEN=%d\n",
                        __FILE__, __PRETTY_FUNCTION__, __LINE__, group,
                        keys[j], value, MAX_PASSWORD_LEN);
				free(value);
				goto error;
            }
            if (NULL == strncpy(user->password, value,MAX_PASSWORD_LEN)) {
                printf("strcpy value to user->db_password failed\n");
				free(value);
				goto error;
            }
            if (strcasecmp(value, "") == 0) {
                user->scramble_len = 1;
                *(user->scramble_password) = '\x00';
            } else {
                user->scramble_len = 21;
                *(user->scramble_password) = '\x14';
                scramble(
                        user->scramble_password + 1,
                        "\x2f\x55\x3e\x74\x50\x72\x6d\x4b\x56\x4c\x57\x54\x7c\x34\x2f\x2e\x37\x6b\x37\x6e",
                        user->password);
            }
        } else if (0 == strncasecmp(CONFIG_DBUSER_DEFAULT_DB, keys[j], strlen(
                CONFIG_DBUSER_DEFAULT_DB))) {
            if (strlen(value) >= MAX_DEFAULT_DB_NAME_LEN) {
                printf(
                        "group=%s, key=%s,value=%s default_db strlen>=MAX_DEFAULT_DB_NAME_LEN=%d\n",
                        group, keys[j], value, MAX_DEFAULT_DB_NAME_LEN);
				free(value);
				goto error;
            }
            if (NULL == strncpy(user->default_db, value,MAX_DEFAULT_DB_NAME_LEN)) {
                printf("strcpy value to user->default_db failed\n");
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_DBUSER_DEFAULT_CHARSET, keys[j], strlen(
				CONFIG_DBUSER_DEFAULT_CHARSET))) {

			if (strncasecmp(value, "gbk", 3) == 0) {
				user->default_charset = 28; /* gbk_chinese_ci */
			} else if (strncasecmp(value, "utf8", 4) == 0 || strncasecmp(value, "utf-8", 5) == 0) {
				user->default_charset = 33;  /* utf8_general_ci */
			} else if (strncasecmp(value, "latin1", 6) == 0) {
				user->default_charset = 8;  /* latin1_swedish_ci */
			} else if (strncasecmp(value, "binary", 6) == 0) {
				user->default_charset = 63; /* binary */
			} else {
				printf("unknown default_charset\n");
				free(value);
				goto error;
			}
			
		} else if (0 == strncasecmp(CONFIG_DBUSER_CLUSTER_NAME, keys[j],
                strlen(CONFIG_DBUSER_CLUSTER_NAME))) {
            if (strlen(value) >= MAX_CLUSTER_NAME_LEN) {
                printf(
                        "group=%s, key=%s,value=%s cluster_name strlen>=MAX_CLUSTER_NAME_LEN=%d\n",
                        group, keys[j], value, MAX_CLUSTER_NAME_LEN);
				free(value);
				goto error;
            }
            snprintf(cluster_name,sizeof(cluster_name),"%s",value);
        }

        free(value);
    }

    if (0 > is_valid_str(user->username)) {
        printf("config db_username is not valid\n");
		goto error;
    }
    if (0 > is_valid_str(user->default_db)) {
        printf("config db_default_db is not valid\n");
		goto error;
    }

    cluster *clus = g_hash_table_lookup(config->clusters, cluster_name);
    if (clus == NULL) {
        printf("no cluster name %s existed", value);
		goto error;
    }
    user->clus = clus;

    db_user *temp_user;
    if (is_update == 1 && NULL != (temp_user = g_hash_table_lookup(
            config->db_user, user->username)) ) {

        if(my_strncasestr(user->password, temp_user->password, MAX_PASSWORD_LEN, MAX_CLUSTER_NAME_LEN, 1) != 1){
            snprintf(temp_user->password,MAX_PASSWORD_LEN,"%s",user->password);
        }
        if (my_strncasestr(temp_user->clus->cluster_name,
                user->clus->cluster_name, MAX_CLUSTER_NAME_LEN,
                MAX_CLUSTER_NAME_LEN, 1) != 1) {
            temp_user->clus = clus;
        }
        temp_user->is_old = config->user_update_flag;

        free(user);
        user = NULL;
		for(j = 0; j < k_cnt; j++){
			free(keys[j]);
		}
		free(keys);
        return 0;
    }

    GHashTable *t;
    if (NULL == (t = g_hash_table_new(g_str_hash, g_str_equal))) {
        printf("%s:%s:%d  g_hash_table_new failed", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
		goto error;
    }
    if (user->default_db[0] != '\0') {
        conn_pool_queue *q;
        if (NULL == (q = (conn_pool_queue*) conn_pool_queue_create())) {
            printf("conn_pool_queue_create() return null");
			goto error;
        }
        g_hash_table_insert(t, user->default_db, q);
    }
    if (user->username[0] == '\0') {
        printf("%s:%s:%d  db_username is NULL failed", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        g_hash_table_destroy(t);
		goto error;
    }
    g_hash_table_insert(clus->db_conn_pools, user->username, t);

    g_hash_table_insert(config->db_user, user->username, user);

    user->is_old = config->user_update_flag;

    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);

    return 0;

error:
	free(user);
	for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
	return -1;


}
int init_cluster(network_server_config *config, GKeyFile *conf_file,
        gchar *group, int is_update) {

    GError *error = NULL;
    gchar **keys = NULL;
    gchar *value = NULL;

    cluster *clus;

    if (NULL == (clus = (cluster*) cluster_create())) {
        printf("%s:%s:%d cluster_create faild\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return -1;
    }

    gsize k_cnt;
    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("%s:%s:%d group=%s doesn't have any key\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, group);
		free(clus);
        return -1;
    }

    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_CLUSTER_NAME, keys[j], strlen(
                CONFIG_CLUSTER_NAME))) {
            if (strlen(value) >= MAX_CLUSTER_NAME_LEN) {
                printf(
                        "group=%s, key=%s, value=%s username strlen >= MAX_CLUSTER_NAME_LEN=%d\n",
                        group, keys[j], value, MAX_CLUSTER_NAME_LEN);
				free(value);
				goto error;
            }

            if (NULL == strncpy(clus->cluster_name, value,MAX_CLUSTER_NAME_LEN)) {
                printf("strcpy value to cluster->cluster_name failed\n");
				free(value);
				goto error;
            }
            
        } else {
            printf("%s:%s:%d init_cluster faild!", __FILE__,
                    __PRETTY_FUNCTION__, __LINE__);
			free(value);
			goto error;
        }

        free(value);
    }

    if (0 > is_valid_str(clus->cluster_name)) {
        printf("config cluster_name is not valid\n");
		goto error;
    }
    g_hash_table_insert(config->clusters, clus->cluster_name, clus);

    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return 0;

error:
	free(clus);
    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
    return -1;
}

int is_new_network_database(network_server_config *config,
        network_database *db, GPtrArray *dbs,int is_slave,int is_load_from_zk) {
    network_database *cur_db = NULL;
    int dbs_len = dbs->len;

    int i;
    for (i = 0; i < dbs_len; i++) {
        cur_db = g_ptr_array_index(dbs, i);
        if (my_strncasestr(db->addr.addr_name, cur_db->addr.addr_name,
                MAX_IP_LEN, MAX_IP_LEN, 1) == 1 && db->addr.port
                == cur_db->addr.port) {

			if(is_load_from_zk == 0) {
				if(is_slave == 0){
					cur_db->is_old = cur_db->clus->w_update_flag;
				}else{
					cur_db->is_old = cur_db->clus->r_update_flag;
				}
			}
            network_database_free(db);
            return 0;
        }
    }
    return 1;
}

int init_network_database_by_group(network_server_config *config,
        GKeyFile *conf_file, gchar *group, int is_slave,
        int is_read_from_local, int is_update) {

    GError *error = NULL;
    gchar **keys = NULL;
    gchar *value = NULL;

    network_database *db = NULL;

    network_database *basic_db = NULL;

    GPtrArray *dbs = NULL;
	db_group_info *bd = NULL;

    FILE *local_conf_file = NULL;
    char conf_file_name[MAX_FILE_NAME_LEN];
    char *zk_path = malloc(sizeof(char) * MAX_ZOOKEEPER_PATH_LEN);
    if (zk_path == NULL) {
        printf("%s:%s:%d zk_path malloc failed", __FILE__, __PRETTY_FUNCTION__,
                __LINE__);
        return -1;
    }

    int db_num = 0;
    if (is_read_from_local == 0) {
        if (NULL == (basic_db = network_database_create())) {
            printf(
                    "basic_db:network_database_creat() return null :not enough memory\n");
			free(zk_path);
            return -1;
        }
        snprintf(basic_db->group_name,sizeof(basic_db->group_name),"%s",group);
        dbs = g_ptr_array_new();
        if (dbs == NULL) {
            printf("%s:%s:%d g_ptr_array_new failed \n", __FILE__,
                    __PRETTY_FUNCTION__, __LINE__);
			free(zk_path);
			free(basic_db);
            return -1;
        }
    } else {
        if (NULL == (db = network_database_create())) {
            printf("network_database_creat() return null :not enough memory\n");
			free(zk_path);
            return -1;
        }
        db->connect_timeout = CONFIG_DB_CONNECT_TIMEOUT_DEFAULT;
        db->time_reconnect_interval = CONFIG_DB_TIME_RECONNECT_INTERVAL_DEFAULT;
    }

    gsize k_cnt;
    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("group=%s doesn't have any key\n", group);
		free(zk_path);
		if(db != NULL){
			free(db);
		}
		if(basic_db != NULL){
			free(basic_db);
		}
        return -1;
    }

    cluster *clus = NULL;
    int a_index = 0;

    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_DB_PORT, keys[j], strlen(CONFIG_DB_PORT))) {
            db->addr.port = strtoul(value, NULL, 10);
            if (0 == is_port_valid(db->addr.port)) {
                printf("%s:port=%d should in the range of [1, 65535)\n", group,
                        db->addr.port);
				free(value);
				goto error;
            }
            db->addr.addr_ip.sin_port = htons(db->addr.port);
        } else if (0 == strncasecmp(CONFIG_DB_HOST, keys[j], strlen(
                CONFIG_DB_HOST))) {
            
            if (is_read_from_local == 0) {
                int zk_ret;
                struct String_vector child_paths;
                zk_ret = zoo_get_children(config->zh, value, 1, &child_paths);

                if (zk_ret != ZOK) {
                    const char *zk_error = zerror(zk_ret);
                    printf("%s:%s:%d zk node %s error %s\n", __FILE__,
                            __PRETTY_FUNCTION__, __LINE__, value, zk_error);
					free(value);
					goto error;
                }

                int i;
                char *cp;
                db_num = child_paths.count;
                char child_path[MAX_ZOOKEEPER_PATH_LEN];

                a_index = config->zk_path_array->len;
                snprintf(zk_path, MAX_ZOOKEEPER_PATH_LEN,"%s", value);
                g_ptr_array_add(config->zk_path_array, zk_path);

                snprintf(conf_file_name, MAX_FILE_NAME_LEN, "%s/%d.conf",
                        config->zk_conf_dir, a_index);
                if (NULL == (local_conf_file = fopen(conf_file_name, "w+"))) {
                    printf(
                            "open zk local conf file failed file_name %s group=%s\n",
                            conf_file_name, group);
					free(value);
					goto error;
                }

                int f_len = strlen(value) + 1;
                int c_len;
                for (i = 0; i < db_num; i++) {
                    network_database *curr_db;
                    if (NULL == (curr_db = network_database_create())) {
                        printf(
                                "%s:%s:%d network_database_creat() return null :not enough memory\n",
                                __FILE__, __PRETTY_FUNCTION__, __LINE__);
						free(value);
						goto error;
                    }
                    cp = child_paths.data[i];
                    c_len = strlen(cp) + 1;

                    snprintf(child_path, f_len,"%s", value);
                    child_path[f_len - 1] = '/';
                    snprintf(child_path + f_len, c_len,"%s", cp);

                    if (set_db_address_from_zk(config->zh, child_path, curr_db,
                            0) != 0) {
                        printf("%s:%s:%d zk node %s set address failed \n",
                                __FILE__, __PRETTY_FUNCTION__, __LINE__, cp);
						free(value);
						goto error;
                    }
                    curr_db->connect_timeout
                            = CONFIG_DB_CONNECT_TIMEOUT_DEFAULT;
                    curr_db->time_reconnect_interval
                            = CONFIG_DB_TIME_RECONNECT_INTERVAL_DEFAULT;

					int is_new_db = is_new_network_database(config,curr_db,dbs,is_slave,1);
					if(is_new_db == 1) {
						g_ptr_array_add(dbs, curr_db);
					}
                }
				db_num = dbs->len;
                deallocate_String_vector(&child_paths);

                snprintf(basic_db->zk_path,sizeof(basic_db->zk_path),"%s",value);
            } else {
                snprintf(db->addr.addr_name, MAX_IP_LEN,"%s", value);
                db->addr.addr_len = sizeof(db->addr.addr_ip);
                db->addr.addr_ip.sin_family = AF_INET;
                if (0 == inet_aton(value, &(db->addr.addr_ip.sin_addr))) {
                    printf("[%s] %s=%s is not a valid ip\n", group, keys[j],
                            value);
					free(value);
					goto error;
                }

                db->key = str_hash(db->addr.addr_name);
            }

        } else if (0 == strncasecmp(CONFIG_DB_MAX_CONNECTIONS, keys[j], strlen(
                CONFIG_DB_MAX_CONNECTIONS))) {
            if (is_read_from_local == 0) {
                if (0 >= (basic_db->max_connections = strtoul(value, NULL, 10))) {
                    printf("%s:max_connections=%d should > 0\n", group,
                            basic_db->max_connections);
					free(value);
					goto error;
                }
                int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    if (0 >= (curr_db->max_connections = strtoul(value, NULL,
                            10))) {
                        printf("%s:max_connections=%d should > 0\n", group,
                                curr_db->max_connections);
						free(value);
						goto error;
                    }
                }
            } else {
                if (0 >= (db->max_connections = strtoul(value, NULL, 10))) {
                    printf("%s:max_connections=%d should > 0\n", group,
                            db->max_connections);
					free(value);
					goto error;
                }
            }

        } else if (0 == strncasecmp(CONFIG_DB_MIN_CONNECTIONS, keys[j], strlen(
                CONFIG_DB_MIN_CONNECTIONS))) {
            if (is_read_from_local == 0) {
                if (0 >= (basic_db->min_connections = strtoul(value, NULL, 10))) {
                    printf("%s:min_connections=%d should > 0\n", group,
                            basic_db->max_connections);
					free(value);
					goto error;
                }
                int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    if (0 >= (curr_db->min_connections = strtoul(value, NULL,
                            10))) {
                        printf("%s:min_connections=%d should > 0\n", group,
                                curr_db->max_connections);
						free(value);
						goto error;
                    }
                }
            } else {
                if (0 >= (db->min_connections = strtoul(value, NULL, 10))) {
                    printf("%s:min_connections=%d should > 0\n", group,
                            db->max_connections);
					free(value);
					goto error;
                }
            }
		} else if (0 == strncasecmp(CONFIG_DB_RESERVED_MASTER_CONNECTIONS, keys[j],
			strlen(CONFIG_DB_RESERVED_MASTER_CONNECTIONS))) {
			
			long int temp_value = strtol(value, NULL, 10);
			if (temp_value < 0) {
				printf("%s:reserved_master_connections=%ld should >= 0\n", group, temp_value);
				free(value);
				goto error;
			}
			
			if (is_read_from_local == 0) {
				basic_db->reserved_master_connections = (guint)temp_value;

				int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    curr_db->reserved_master_connections = (guint)temp_value;
                }
            } else {
				db->reserved_master_connections = (guint)temp_value;
			}
        } else if (0 == strncasecmp(CONFIG_DB_CONNECT_TIMEOUT, keys[j], strlen(
                CONFIG_DB_CONNECT_TIMEOUT))) {
            if (is_read_from_local == 0) {
                if (0 >= (basic_db->connect_timeout = strtoul(value, NULL, 10))) {
                    printf("%s:connect_timeout=%d should > 0\n", group,
                            basic_db->connect_timeout);
					free(value);
					goto error;
                }
                int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    if (0 >= (curr_db->connect_timeout = strtoul(value, NULL,
                            10))) {
                        printf("%s:connect_timeout=%d should > 0\n", group,
                                curr_db->connect_timeout);
						free(value);
						goto error;
                    }
                }
            } else {
                if (0 >= (db->connect_timeout = strtoul(value, NULL, 10))) {
                    printf("%s:connect_timeout=%d should > 0\n", group,
                            db->connect_timeout);
					free(value);
					goto error;
                }
            }
        } else if (0 == strncasecmp(CONFIG_DB_TIME_RECONNECT_INTERVAL, keys[j],
                strlen(CONFIG_DB_TIME_RECONNECT_INTERVAL))) {
            if (is_read_from_local == 0) {
                if (0 > (basic_db->time_reconnect_interval = strtoul(value,
                        NULL, 10))) {
                    printf("%s:time_reconnect_interval=%d should > 0\n", group,
                            basic_db->time_reconnect_interval);
					free(value);
					goto error;
                }
                int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    if (0 > (curr_db->time_reconnect_interval = strtoul(value,
                            NULL, 10))) {
                        printf("%s:time_reconnect_interval=%d should > 0\n",
                                group, curr_db->time_reconnect_interval);
						free(value);
						goto error;
                    }
                }
            } else {
                if (0 > (db->time_reconnect_interval = strtoul(value, NULL,
                                10))) {
                    printf("%s:time_reconnect_interval=%d should > 0\n", group,
                            db->time_reconnect_interval);
					free(value);
					goto error;
                }
            }
        } else if (0 == strncasecmp(CONFIG_DB_WEIGHT, keys[j], strlen(
                CONFIG_DB_WEIGHT))) {
            if (is_read_from_local == 1) {
                if (0 > (db->weight = strtoul(value, NULL, 10))) {
                    printf("%s:weight=%d should > 0\n", group, db->weight);
					free(value);
					goto error;
                }
            }
        } else if (0 == strncasecmp(CONFIG_DB_CLUSTER_NAME, keys[j], strlen(
                CONFIG_DB_CLUSTER_NAME))) {
            clus = g_hash_table_lookup(config->clusters, value);
            if (clus == NULL) {
                printf("no cluster name %s existed", value);
				free(value);
				goto error;
            }
            if (is_read_from_local == 0) {
                basic_db->clus = clus;
                int i;
                network_database *curr_db;
                for (i = 0; i < db_num; i++) {
                    curr_db = g_ptr_array_index(dbs, i);
                    curr_db->clus = clus;
                }
            } else {
                db->clus = clus;
            }
        } else if (0 == strncasecmp(CONFIG_DB_HOST_NAME, keys[j], strlen(
                CONFIG_DB_HOST_NAME))) {
            if (is_read_from_local == 1) {
                if (strlen(value) >= MAX_HOST_NAME_LEN) {
                    printf(
                            "group=%s, key=%s, value=%s hostname strlen >= MAX_HOST_NAME_LEN=%d\n",
                            group, keys[j], value, MAX_HOST_NAME_LEN);
					free(value);
					goto error;
                }
                if (NULL == strncpy(db->host_name, value,MAX_HOST_NAME_LEN)) {
                    printf("strcpy value to db->host_name failed\n");
					free(value);
					goto error;
                }
            }
        }

        free(value);
    }

    if (is_read_from_local == 0) {
        if (basic_db->min_connections > basic_db->max_connections
                || basic_db->min_connections < 0 || basic_db->max_connections
                <= 0) {
            printf(
                    "%s min_connections=%d, max_connections=%d is invalid, should be :min_connections <= max_connections && min_connections >= 0 && max_connections > 0\n",
                    group, basic_db->min_connections, basic_db->max_connections);
			goto error;
        }
        int i;
        network_database *curr_db;
        for (i = 0; i < db_num; i++) {
            curr_db = g_ptr_array_index(dbs, i);
            if(is_slave == 0){
                curr_db->is_old = curr_db->clus->w_update_flag;
            } else {

                curr_db->is_old = curr_db->clus->r_update_flag;
            }
            snprintf(curr_db->group_name,sizeof(curr_db->group_name),"%s",group);
            if (is_slave == 0) {
                g_ptr_array_add(clus->master_dbs, curr_db);
                curr_db->ms = MS_MASTER;
            } else {
                g_ptr_array_add(clus->slave_dbs, curr_db);
                curr_db->ms = MS_SLAVE;
            }
        }

        bd = (db_group_info*) calloc(1, sizeof(db_group_info));
		if(bd == NULL) {
            printf("%s:%s:%d db_group_info is null\n",
                    __FILE__, __PRETTY_FUNCTION__, __LINE__);
			goto error;
		}
        bd->basic_db = basic_db;
        bd->is_slave = is_slave;
        bd->array_index = a_index;

        g_hash_table_insert(config->basic_db_info, basic_db->zk_path, bd);

        if (local_conf_file == NULL) {
            printf("%s:%s:%d local_conf_file is null and is_update == 0\n",
                    __FILE__, __PRETTY_FUNCTION__, __LINE__);
			goto error;
        }

        int put_ret;
        char conf_item[MAX_CONF_ITEM_LEN];
        for (i = 0; i < db_num; i++) {
            curr_db = g_ptr_array_index(dbs, i);

            snprintf(conf_item, sizeof(conf_item), "\n[%s_%d]\n",
                    curr_db->group_name, i);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }

            snprintf(conf_item, sizeof(conf_item), "host=%s\n",
                    curr_db->addr.addr_name);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }

            snprintf(conf_item, sizeof(conf_item), "zk_path=%s\n", zk_path);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }

            snprintf(conf_item, sizeof(conf_item), "port=%d\n",
                    curr_db->addr.port);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }

            snprintf(conf_item, sizeof(conf_item), "name=%s\n",
                    curr_db->host_name);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }

            snprintf(conf_item, sizeof(conf_item), "cluster_name=%s\n",
                    curr_db->clus->cluster_name);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }
            snprintf(conf_item, sizeof(conf_item), "max_connections=%d\n",
                    curr_db->max_connections);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }
            snprintf(conf_item, sizeof(conf_item), "connect_timeout=%d\n",
                    curr_db->connect_timeout);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }
            snprintf(conf_item, sizeof(conf_item),
                    "time_reconnect_interval=%d\n",
                    curr_db->time_reconnect_interval);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }
            snprintf(conf_item, sizeof(conf_item), "weight=%d\n",
                    curr_db->weight);
            put_ret = fputs(conf_item, local_conf_file);
            if (put_ret == EOF) {
                printf("%s:%s:%d fputs failed\n",__FILE__, __PRETTY_FUNCTION__, __LINE__);
				goto error;
            }
        }

        if (EOF == fclose(local_conf_file)) {
            printf("%s:%s:%d  flcose failed filename %s\n", __FILE__,
                    __PRETTY_FUNCTION__, __LINE__, conf_file_name);
			goto error;
        }

        struct stat conf;
        if(0 != stat(conf_file_name,&conf)){
            log_warning(logger,"read the status of %s failed",conf_file_name);
			goto error;
        }

        bd->modify_time = conf.st_mtime;

        g_ptr_array_free(dbs, 0);

    } else {
		if(zk_path != NULL) {
			free(zk_path);
			zk_path = NULL;
		}
        if (db->min_connections > db->max_connections || db->min_connections
                < 0 || db->max_connections <= 0) {
            printf(
                    "%s min_connections=%d, max_connections=%d is invalid, should be :min_connections <= max_connections && min_connections >= 0 && max_connections > 0\n",
                    group, db->min_connections, db->max_connections);
			goto error;
        }
        GPtrArray *dbs = NULL;
        cluster *clus = g_hash_table_lookup(config->clusters,
                db->clus->cluster_name);

        if (is_slave == 0) {
            dbs = clus->master_dbs;
            db->ms = MS_MASTER;
        } else {
            dbs = clus->slave_dbs;
            db->ms = MS_SLAVE;
        }
        if (is_update == 1) {
            if (is_new_network_database(config, db, dbs,is_slave,0) == 0) {

                log_load(logger,"not new network_database");

				for(j = 0; j < k_cnt; j++){
					free(keys[j]);
				}
				free(keys);
                return 0;
            }

        }
        g_ptr_array_add(dbs, db);
        snprintf(db->group_name,sizeof(db->group_name),"%s",group);
        if(is_slave == 0){
            db->is_old = db->clus->w_update_flag;
        } else {
            db->is_old = db->clus->r_update_flag;
        }
	}

	for(j = 0; j < k_cnt; j++){
		free(keys[j]);
    }
    free(keys);

    return 0;

error:

    for(j = 0; j < k_cnt; j++){
        free(keys[j]);
    }
    free(keys);
	if(db != NULL){
		free(db);
	}
	if(zk_path != NULL) {
		free(zk_path);
	}
	return -1;
}

int init_mysql_proxy_layer(network_server_config *config, GKeyFile *conf_file) {

    gchar *group = CONFIG_MPL_GROUP;

    gchar **keys = NULL;
    gchar *value = NULL;
    GError *error = NULL;

    gsize k_cnt;
    if ((NULL == (keys = g_key_file_get_keys(conf_file, group, &k_cnt, &error)))
            || k_cnt <= 0) {
        printf("group=%s doesn't have any key\n", group);
        return -1;
    }

    int j;
    for (j = 0; j < k_cnt; j++) {
        if (NULL == (value = g_key_file_get_string(conf_file, group, keys[j],
                &error))) {
            printf("group=%s, key=%s has no value\n", group, keys[j]);
			goto error;
        }
        if (0 == strncasecmp(CONFIG_MPL_PORT, keys[j], strlen(CONFIG_MPL_PORT))) {
            config->port = strtoul(value, NULL, 10);
            if (0 == is_port_valid(config->port)) {
                printf("MPL:port=%d should in the range of [1, 65535)\n",
                        config->port);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_HOST, keys[j], strlen(
                CONFIG_MPL_ZK_HOST))) {
            snprintf(config->zk_host, sizeof(config->zk_host),"%s", value);
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_CONF_DIR, keys[j], strlen(
                CONFIG_MPL_ZK_CONF_DIR))) {
            snprintf(config->zk_conf_dir, sizeof(config->zk_conf_dir),"%s", value);
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_LOG, keys[j], strlen(
                CONFIG_MPL_ZK_LOG))) {
            snprintf(config->zk_log, sizeof(config->zk_log),"%s", value);
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_ENABLE, keys[j], strlen(
                CONFIG_MPL_ZK_ENABLE))) {
            config->is_zk_enable = strtoul(value, NULL, 10);
            if (config->is_zk_enable != 0 && config->is_zk_enable != 1) {
                printf("MPL:is_zk_enable=%d should be 0 or 1 \n",
                        config->is_zk_enable);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_MAX_THREADS, keys[j], strlen(
                CONFIG_MPL_MAX_THREADS))) {
            config->max_threads = strtoul(value, NULL, 10);
            if (config->max_threads <= 0) {
                printf("MPL:max_threads=%d should > 0\n", config->max_threads);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_BACKLOG, keys[j], strlen(
                CONFIG_MPL_BACKLOG))) {
            config->backlog = strtoul(value, NULL, 10);
            if (config->backlog <= 0) {
                printf("MPL:backlog=%d should > 0\n", config->backlog);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_LOG_DIR, keys[j], strlen(
                CONFIG_MPL_LOG_DIR))) {
            snprintf(config->log_dir, sizeof(config->log_dir),"%s", value);
        } else if (0 == strncasecmp(CONFIG_MPL_LOG_FILENAME, keys[j], strlen(
                CONFIG_MPL_LOG_FILENAME))) {
            snprintf(config->log_filename, sizeof(config->log_filename),"%s", value);
        } else if (0 == strncasecmp(CONFIG_MPL_LOG_MAXSIZE, keys[j], strlen(
                CONFIG_MPL_LOG_MAXSIZE))) {
            config->log_maxsize = strtoul(value, NULL, 10);
            if (config->log_maxsize <= 0 || config->log_maxsize > 10240) {
                printf("MPL:log_maxsize=%d should > 0 and <= 10240\n",
                        config->log_maxsize);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_TIMEOUT_CHECK_INTERVAL, keys[j],
                strlen(CONFIG_MPL_TIMEOUT_CHECK_INTERVAL))) {
            config->timeout_check_interval = strtoul(value, NULL, 10);
            if (config->timeout_check_interval <= 0) {
                printf("MPL:timeout_check_interval=%ld should > 0",
                        config->timeout_check_interval);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_CLIENT_TIMEOUT, keys[j], strlen(
                CONFIG_MPL_CLIENT_TIMEOUT))) {
            config->client_timeout = strtoul(value, NULL, 10);
            if (config->client_timeout <= 0) {
                printf("MPL:client_timeout=%ld should > 0",
                        config->client_timeout);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_SERVER_TIMEOUT_SHORT, keys[j],
                strlen(CONFIG_MPL_SERVER_TIMEOUT_SHORT))) {
            config->server_timeout_short = strtoul(value, NULL, 10);
            if (config->server_timeout_short <= 0) {
                printf("MPL:server_timeout_short=%ld should > 0",
                        config->server_timeout_short);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_SERVER_TIMEOUT, keys[j], strlen(
                CONFIG_MPL_SERVER_TIMEOUT))) {
            config->server_timeout = strtoul(value, NULL, 10);
            if (config->server_timeout <= 0) {
                printf("MPL:server_timeout=%ld should > 0",
                        config->server_timeout);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_WRITE_TIME_INTERVAL, keys[j],
                strlen(CONFIG_MPL_WRITE_TIME_INTERVAL))) {
            config->write_time_interval = strtoul(value, NULL, 10);
            if (config->write_time_interval <= 0) {
                printf("MPL:write_time_interval=%ld should > 0",
                        config->write_time_interval);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_LOG_QUERY_MIN_TIME, keys[j],
                strlen(CONFIG_MPL_LOG_QUERY_MIN_TIME))) {
            config->log_query_min_time = strtoul(value, NULL, 10);
        } else if (0 == strncasecmp(CONFIG_MPL_LOG_LEVEL, keys[j], strlen(
                CONFIG_MPL_LOG_LEVEL))) {
            config->log_level = strtoul(value, NULL, 10);
        } else if (0 == strncasecmp(
                CONFIG_MPL_CONN_POOL_SOCKET_MAX_SERVE_CLIENT_TIMES, keys[j],
                strlen(CONFIG_MPL_CONN_POOL_SOCKET_MAX_SERVE_CLIENT_TIMES))) {
            config->conn_pool_socket_max_serve_client_times = strtoul(value,
                    NULL, 10);
            if (config->conn_pool_socket_max_serve_client_times <= 0) {
                printf(
                        "MPL:conn_pool_socket_max_serve_client_times=%ld should > 0\n",
                        config->conn_pool_socket_max_serve_client_times);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_SO_PATH_PREFIX, keys[j], strlen(
                CONFIG_MPL_SO_PATH_PREFIX))) {
            if (load_hook_so(value, config->h_array) == -1) {
                printf("MPL:load_hoo_so failed so_path=%s", value);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_PROXY_STATUS_INTERVAL, keys[j], strlen(
                CONFIG_MPL_PROXY_STATUS_INTERVAL))) {
            config->proxy_status_interval = strtoul(value, NULL, 10);
            if (config->proxy_status_interval < 0) {
                printf("MPL:proxy_status_interval=%d should >= 0",
                        config->proxy_status_interval);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_AUTOLOAD_LOCAL_CONF_ENABLE, keys[j], strlen(
                CONFIG_MPL_AUTOLOAD_LOCAL_CONF_ENABLE))) {
            config->is_autoload_enable = strtoul(value, NULL, 10);
            if (config->is_autoload_enable != 0 && config->is_autoload_enable != 1) {
                printf("MPL:is_autoload_enable=%d should be 0 or 1 \n",
                        config->is_autoload_enable);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_TIMEOUT, keys[j], strlen(
                CONFIG_MPL_ZK_TIMEOUT))) {
            config->zk_timeout = strtoul(value, NULL, 10);
            if (config->zk_timeout <= 0) {
                printf("MPL:zk_timeout=%d should greater than 0 \n",
                        config->zk_timeout);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_ZK_INTERVAL, keys[j], strlen(
                CONFIG_MPL_ZK_INTERVAL))) {
            config->zk_interval = strtoul(value, NULL, 10);
            if (config->zk_interval <= 0) {
                printf("MPL:zk_interval=%d should greater than 0 \n",
                        config->zk_interval);
				free(value);
				goto error;
            }
        } else if (0 == strncasecmp(CONFIG_MPL_MAX_QUERY_SIZE, keys[j], strlen(
                CONFIG_MPL_MAX_QUERY_SIZE))) {
            config->max_query_size = strtoul(value, NULL, 10);
            if (config->max_query_size <= 50 || config->max_query_size > 524288) {
                printf("MPL:max_query_size=%d should >50 or <= 524288 \n",
                        config->max_query_size);
				free(value);
				goto error;
            }
			config->max_query_size = config->max_query_size * 1024;
        } else if (0 == strncasecmp(CONFIG_MPL_MAX_QUERY_NUM, keys[j], strlen(
                CONFIG_MPL_MAX_QUERY_NUM))) {
            config->max_query_num = strtoul(value, NULL, 10);
            if (config->max_query_num <= 0) {
                printf("MPL:max_query_num=%d should greater than 0 \n",
                        config->max_query_num);
				free(value);
				goto error;
            }
        }
        free(value);
    }

    for (j = 0; j < k_cnt; j++) {
        free(keys[j]);
    }
    free(keys);
    return 0;

error:

    for (j = 0; j < k_cnt; j++) {
        free(keys[j]);
    }
    free(keys);
    return -1;
}

network_server_config* get_default_network_server_config() {

    network_server_config *config;
    if (NULL == (config = calloc(1, sizeof(network_server_config)))) {
        printf("not enough memory\n");
        return NULL;
    }
    if (NULL == (config->users = g_hash_table_new(g_str_hash, g_str_equal))) {
        printf("config->users = g_hash_table_new() return null\n");
        return NULL;
    }
    if (NULL == (config->auth_ips = g_ptr_array_new())) {
        printf("config->auth_ips = g_ptr_array_new() return null\n");
        return NULL;
    }
    if (NULL == (config->db_user = g_hash_table_new(g_str_hash, g_str_equal))) {
        printf("config->db_user = g_hash_table_new() return NULL\n");
        return NULL;
    }
    if (NULL == (config->clusters = g_hash_table_new(g_str_hash, g_str_equal))) {
        printf("config->clusters = g_hash_table_new() return NULL\n");
        return NULL;
    }
    
    if (NULL == (config->basic_db_info = g_hash_table_new(g_str_hash,
            g_str_equal))) {
        printf("config->basic_db_info = g_hash_table_new() return null\n");
        return NULL;
    }

    if (NULL == (config->zk_path_array = g_ptr_array_new())) {
        printf("config->zk_path_array = g_ptr_array_new() return null\n");
        return NULL;
    }
/*    if (NULL == (config->pid_array = g_array_new(0, 0, sizeof(pid_t)))) {
        printf("config->pid_array = g_array_new() return null\n");
        return NULL;
    }*/

    if(NULL == (config->sessions = g_hash_table_new(g_int_hash,g_int_equal))){
            printf("config->sessions = g_hash_table_new() return null\n");
            return NULL;
    }



    //二次开发钩子
    config->h_array = hook_array_create();

    if (config->h_array == NULL) {
        printf("%s:%s:%d hook_array_create failed\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return NULL;
    }

    config->port = 8888;
    config->backlog = 50;
    config->max_threads = 2;
    config->reconnect_times = CONFIG_MPL_RECONNECT_TIMES_DEFAULT;
    config->timeout_check_interval = 600;
    config->client_timeout = 1200;
    config->server_timeout = 1200;
    config->log_maxsize = 1800;
    config->log_level = 15;
    config->conn_pool_socket_max_serve_client_times = 500;
    config->zh = NULL;
    config->user_update_flag = 0;

    config->mmap_flag = 1;
    config->proxy_status_interval = 0;
	config->is_autoload_enable = 0;
	config->zk_timeout = 30000;
	config->zk_interval = 60;
	config->max_query_size = 1024*3*1024;
	config->max_query_num = 1000;

    return config;
}

network_server_config* get_network_server_config(char *conf_path) {

    if (NULL == conf_path) {
        printf("get_network_server_config conf_path = null\n");
        return NULL;
    }

    network_server_config *config;

    if (NULL == (config = get_default_network_server_config())) {
        printf("get_default_network_server_config return null\n");
        return NULL;
    }

    GKeyFile *conf_file;

    if (NULL == (conf_file = g_key_file_new())) {
        printf("g_key_file_new() return null\n");
        return NULL;
    }

    if (0 == g_key_file_load_from_file(conf_file, conf_path, 0, NULL)) {
        printf("g_key_file_load_from_file() failed conf_path=%s\n", conf_path);
        return NULL;
    }

    gsize g_cnt = -1;
    gchar **groups = NULL;

    if ((NULL == (groups = g_key_file_get_groups(conf_file, &g_cnt))) || g_cnt
            <= 0) {
        printf("config file=%s doesn't have any group\n", conf_path);
        return NULL;
    }

    int i;
    for (i = 0; i < g_cnt; i++) {

        if (NULL != strstr(groups[i], CONFIG_MPL_GROUP)) {
            if (-1 == init_mysql_proxy_layer(config, conf_file)) {
                printf("init_mysql_proxy_layer failed group=%s\n", groups[i]);
                return NULL;
            }

            if (config->is_zk_enable == 1) {
                //启动zookeeper客户端
                if (-1 == init_zookeeper(config, config->zk_host,
                        config->zk_log,1)) {
                    printf("init_zookeeper failed group=%s\n", groups[i]);
                    return NULL;
                }
            }
        } else if (NULL != strstr(groups[i], CONFIG_CLUSTER_GROUP)) {
            if (-1 == init_cluster(config, conf_file, groups[i], 0)) {
                printf("init_cluster failed group=%s\n", groups[i]);
                return NULL;
            }
        } else if (NULL != strstr(groups[i], CONFIG_DB_MASTER_GROUP_PREFIX)) {
            if (config->is_zk_enable == 1) {
                if (-1 == init_network_database_by_group(config, conf_file,
                        groups[i], 0, 0, 0)) {
                    printf("init_network_database_by_group failed group=%s\n",
                            groups[i]);
                    return NULL;
                }
            } else {
                if (-1 == init_network_database_by_group(config, conf_file,
                        groups[i], 0, 1, 0)) {
                    printf("init_network_database_by_group failed group=%s\n",
                            groups[i]);
                    return NULL;
                }
            }
        } else if (NULL != strstr(groups[i], CONFIG_DB_SLAVE_GROUP_PREFIX)) {
            if (config->is_zk_enable == 1) {
                if (-1 == init_network_database_by_group(config, conf_file,
                        groups[i], 1, 0, 0)) {
                    printf("init_network_database_by_group failed group=%s\n",
                            groups[i]);
                    return NULL;
                }
            } else {
                if (-1 == init_network_database_by_group(config, conf_file,
                        groups[i], 1, 1, 0)) {
                    printf("init_network_database_by_group failed group=%s\n",
                            groups[i]);
                    return NULL;
                }
            }

        } else if (NULL != strstr(groups[i], CONFIG_DBUSER_GROUP_PREFIX)) {
            if (-1 == init_db_user(config, conf_file, groups[i], 0)) {
                printf("init_db_user failed group=%s\n", groups[i]);
                return NULL;
            }
        }else if (NULL != strstr(groups[i], CONFIG_PRODUCTUSER_GROUP_PREFIX)) {
            if (-1 == init_product_user(config, conf_file, groups[i], 0)) {
                printf("init_product_user failed group=%s\n", groups[i]);
                return NULL;
            }
        } else if (NULL != strstr(groups[i], CONFIG_AUTH_IP_GROUP_PREFIX)) {
            if (-1 == init_auth_ip(config, conf_file, groups[i])) {
                printf("init_auth_ip failed group=%s\n", groups[i]);
                return NULL;
            }
        }
    }
    

    struct stat conf_s;
    if(0 != stat(conf_path,&conf_s)){
        printf("read the status of %s failed",conf_path);
        return NULL;
    }
    config->conf_modify_time = conf_s.st_mtime;


    for(i = 0; i < g_cnt; i++) {
        free(groups[i]);
    }
    free(groups);
    g_key_file_free(conf_file);

    return config;
}
