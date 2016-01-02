#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <glib.h>
#include <glib/ghash.h>
#include <assert.h>
#define __USE_GNU
#include <string.h>
#include "array.h"
#include "log.h"
#include "network.h"
#include "password.h"
#include "jansson.h"

inline int real_read(network_socket *s, byte_array *send_buf, int we_want,
        int *ret_read_len);
inline int network_queue_send_append(byte_array *send_buf,
        const unsigned char *data, int len, unsigned char packet_id,
        int append_data_later);
inline int get_query_type(packet_query *query);
inline int is_read_query(int sql_num);
inline int my_strncasestr(unsigned char *str1, unsigned char *str2, int len1,
        int len2, int ignore_case);
inline void network_socket_free(network_socket *s);
void conn_pool_queue_free(conn_pool_queue *q);

extern inline int byte_array_append_len(byte_array *arr, const unsigned char *data, int len);
extern inline void byte_array_free(byte_array *arr);
extern inline int byte_array_append_size(byte_array *arr, int len, int is_pow);
extern int poll_events_add(poll *p, network_socket *s, unsigned int events);
extern void scramble(char *to, const char *message, const char *password);
extern int poll_events_delete(poll *p, network_socket *s);
extern void log_work(t_logger *logger, network_socket *client, int type);

guint str_hash(char *v) {
    /* 31 bit hash function */
    const signed char *p = v;
    guint32 h = *p;
    if (h){
        for (p += 1; *p != '\0'; p++){
            h = (h << 5) - h + *p;
        }
    }
    return h;
}

inline void cluster_free(cluster *c) {

    if (NULL == c){
        return;
    }
    if (NULL != c->db_conn_pools) {
        g_hash_table_destroy(c->db_conn_pools);
    }
    if (NULL != c->master_dbs){
		while(c->master_dbs->len > 0) {
			network_database* db = g_ptr_array_remove_index(c->master_dbs,c->master_dbs->len - 1);
			if(db != NULL) {
				network_database_free(db);
			}
		}
        g_ptr_array_free(c->master_dbs, 1);
    }

    if (NULL != c->slave_dbs){
		while(c->slave_dbs->len > 0) {
			network_database* db = g_ptr_array_remove_index(c->slave_dbs,c->slave_dbs->len - 1);
			if(db != NULL) {
				network_database_free(db);
			}
		}
        g_ptr_array_free(c->slave_dbs, 1);
    }

    free(c);
    c = NULL;
}
inline cluster* cluster_create() {
    cluster *c = (cluster*) calloc(1, sizeof(cluster));
    if (!c) {
        printf("%s:%s:%d calloc failed c==NULL\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return NULL;
    }
    if (NULL == (c->master_dbs = g_ptr_array_new()) || NULL == (c->slave_dbs
            = g_ptr_array_new()) || NULL == (c->db_conn_pools
            = g_hash_table_new(g_str_hash, g_str_equal))) {
        cluster_free(c);
        return NULL;
    }

    return c;

}

inline hook_array* hook_array_create() {

    hook_array* array = (hook_array*) calloc(1, sizeof(hook_array));

    if (!array) {
        printf("%s:%s:%d malloc failed array==NULL\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return NULL;
    }

    int i = 0;
    int j = 0;
    for (i = 0; i < MAX_HOOK_SO; i++) {
        array->so_names[i] = (char*) calloc(1,sizeof(char) * MAX_HOOK_NAME_LEN);
        if (!(array->so_names[i])) {
            printf("%s:%s:%d malloc failed array->so_name[i]==NULL\n",
                    __FILE__, __PRETTY_FUNCTION__, __LINE__);
            for (j = 0; j < i; j++){
                free(array->so_names[j]);
            }
            free(array);
            array = NULL;
            return NULL;
        }
    }

    for (i = 0; i < MAX_HOOK_SO; i++) {

        array->funcs[i]
                = (hook_func*) calloc(1, sizeof(hook_func) * MAX_HOOK_NUMS);

        if (!(array->funcs[i])) {
            printf("%s:%s:%d malloc failed array->func[i]==NULL\n", __FILE__,
                    __PRETTY_FUNCTION__, __LINE__);
            for (j = 0; j < i; j++){
                free(array->funcs[j]);
            }
            free(array);
            array = NULL;
            return NULL;
        }
    }
    array->so_nums = 0;
    return array;
}

void hook_array_free(hook_array* array) {
    if (!array)
        return;

    int i;

    for (i = 0; i < MAX_HOOK_SO; i++) {
        free(array->so_names[i]);
        free(array->funcs[i]);
    }
    free(array);
    array = NULL;
}

int load_hook_so(char* so_path, hook_array* array) {

    if (!array) {
        printf("%s:%s:%d malloc failed array==NULL\n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return -1;
    }

    void* func_lib = dlopen(so_path, RTLD_NOW);

    if (!func_lib) {
        char* error = dlerror();
        printf("%s:%s:%d dlopen failed error %s \n", __FILE__,
                __PRETTY_FUNCTION__, __LINE__, error);
        return -1;
    }
    snprintf(array->so_names[array->so_nums], MAX_HOOK_NAME_LEN,"%s", so_path);

    int i;
    for (i = 0; i < MAX_HOOK_NUMS; i++) {
        hook_func func;
        dlerror();
        switch (i) {
        case 0:
            func = dlsym(func_lib, "connect_server");
            break;
        case 1:
            func = dlsym(func_lib, "read_auth");
            break;
        case 2:
            func = dlsym(func_lib, "read_query");
            break;
        case 3:
            func = dlsym(func_lib, "read_query_result");
            break;
        case 4:
            func = dlsym(func_lib, "load_balance");
            break;
        }

        char *error = NULL;

        if ((error = dlerror()) != NULL) {
            printf("%s:%s:%d dlsym failed error %s \n", __FILE__,
                    __PRETTY_FUNCTION__, __LINE__, error);
            dlclose(func_lib);
            return -1;
        }
        (array->funcs[array->so_nums])[i] = func;
    }

    (array->so_nums)++;

    return 0;

}

int make_result_set_header_packet(byte_array *send_buf, int type,
        int packet_num) {

    if(0 != byte_array_append_len(send_buf, "\x01\x00\x00\x01", 4)){
        return -1;
    }
    switch (type) {
    case 1:
        if(0 != byte_array_append_len(send_buf, "\x07", 1)){
            return -1;
        }
        break;
    case 2:
        if(0 != byte_array_append_len(send_buf, "\x04", 1)){
            return -1;
        }
        break;
    case 3:
        if(0 != byte_array_append_len(send_buf, "\x05", 1)){
            return -1;
        }
        break;
    }
    return 0;
}

int make_field_packet(byte_array *send_buf, int packet_num, const unsigned char *field,
        int field_len) {

    send_buf->data[send_buf->size] = (unsigned char) ((field_len >> 0) & 0xFF);
    send_buf->size++;
    send_buf->data[send_buf->size] = (unsigned char) ((field_len >> 8) & 0xFF);
    send_buf->size++;
    send_buf->data[send_buf->size] = (unsigned char) ((field_len >> 16) & 0xFF);
    send_buf->size++;

    send_buf->data[send_buf->size] = (unsigned char) ((packet_num >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, field, field_len)){
        return -1;
    }
    return 0;
}

int make_eof_pakcet(byte_array *send_buf, int packet_num) {
    if(0 != byte_array_append_len(send_buf, "\x05\x00\x00", 3)){
        return -1;
    }
    send_buf->data[send_buf->size] = (unsigned char) ((packet_num >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, "\xfe\x00\x00\x02\x00", 5)){
        return -1;
    }
    return 0;
}

int make_raw_data_type1(byte_array *send_buf, int packet_num,
        status_user_and_ip *t) {
    int data_begin = send_buf->size;
    send_buf->size += 4;

    int len = strlen(t->pid);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->pid, len)){
        return -1;
    }


    len = strlen(t->username_and_ip);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->username_and_ip, len)){
        return -1;
    }

    char conn_num[10];
    snprintf(conn_num, 10, "%d", t->proxy_connections);

    len = strlen(conn_num);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, conn_num, len)){
        return -1;
    }

    snprintf(conn_num, 10, "%d", t->db_connections);

    len = strlen(conn_num);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, conn_num, len)){
        return -1;
    }


    len = strlen(t->masters);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->masters, len)){
        return -1;
    }

    len = strlen(t->slaves);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->slaves, len)){
        return -1;
    }

    len = strlen(t->cur_time);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->cur_time, len)){
        return -1;
    }
    int size = send_buf->size - data_begin - 4;

    send_buf->data[data_begin] = (unsigned char) ((size >> 0) & 0xFF);
    send_buf->data[data_begin + 1] = (unsigned char) ((size >> 8) & 0xFF);
    send_buf->data[data_begin + 2] = (unsigned char) ((size >> 16) & 0xFF);
    send_buf->data[data_begin + 3] = (unsigned char) ((packet_num >> 0) & 0xFF);

    return 0;
}

int make_raw_data_type2(byte_array *send_buf, int packet_num,
        status_dbip_and_user *t) {

    int data_begin = send_buf->size;
    send_buf->size += 4;

    int len = strlen(t->pid);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->pid, len)){
        return -1;
    }

    len = strlen(t->dbip_and_user_and_userip);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->dbip_and_user_and_userip, len)){
        return -1;
    }

    char conn_num[10];
    snprintf(conn_num, 10, "%d", t->connection_num);

    len = strlen(conn_num);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, conn_num, len)){
        return -1;
    }

    len = strlen(t->cur_time);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->cur_time, len)){
        return -1;
    }
    int size = send_buf->size - data_begin - 4;

    send_buf->data[data_begin] = (unsigned char) ((size >> 0) & 0xFF);
    send_buf->data[data_begin + 1] = (unsigned char) ((size >> 8) & 0xFF);
    send_buf->data[data_begin + 2] = (unsigned char) ((size >> 16) & 0xFF);
    send_buf->data[data_begin + 3] = (unsigned char) ((packet_num >> 0) & 0xFF);

    return 0;
}

int make_raw_data_type3(byte_array *send_buf, int packet_num,
        status_mysql_proxy_layer *t) {

    int data_begin = send_buf->size;
    send_buf->size += 4;

    int len = strlen(t->pid);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->pid, len)){
        return -1;
    }

    len = strlen(t->vmsize);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->vmsize, len)){
        return -1;
    }


    len = strlen(t->conn_pool_stat);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->conn_pool_stat, len)){
        return -1;
    }

    char conn_num[10];
    snprintf(conn_num, 10, "%d", t->network_socket_pool_num);
    len = strlen(conn_num);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, conn_num, len)){
        return -1;
    }

    len = strlen(t->cur_time);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, t->cur_time, len)){
        return -1;
    }

    int size = send_buf->size - data_begin - 4;

    send_buf->data[data_begin] = (unsigned char) ((size >> 0) & 0xFF);
    send_buf->data[data_begin + 1] = (unsigned char) ((size >> 8) & 0xFF);
    send_buf->data[data_begin + 2] = (unsigned char) ((size >> 16) & 0xFF);
    send_buf->data[data_begin + 3] = (unsigned char) ((packet_num >> 0) & 0xFF);

    return 0;
}


int make_execute_raw_data_last_insert_id(byte_array *send_buf, int packet_num,
		unsigned long long last_insert_id) {
	int data_begin = send_buf->size;
	send_buf->size += 4;

	int len = 0;
	static unsigned char affected_rows[] = "\x00\x00";
	len = sizeof(affected_rows) -1;
	if(0 != byte_array_append_len(send_buf, affected_rows, len)){
		return -1;
	}

	unsigned char id[8];
	memset(id,0,8);

	*((unsigned long long *) (id))= last_insert_id;
	if(0 != byte_array_append_len(send_buf, id, 8)){
		return -1;
	}

	int size = send_buf->size - data_begin - 4;

	send_buf->data[data_begin] = (unsigned char) ((size >> 0) & 0xFF);
	send_buf->data[data_begin + 1] = (unsigned char) ((size >> 8) & 0xFF);
	send_buf->data[data_begin + 2] = (unsigned char) ((size >> 16) & 0xFF);
	send_buf->data[data_begin + 3] = (unsigned char) ((packet_num >> 0) & 0xFF);

	return 0;
}

int make_raw_data_last_insert_id(byte_array *send_buf, int packet_num,
        unsigned long long last_insert_id) {
    int data_begin = send_buf->size;
    send_buf->size += 4;

	char id_num[20];
	snprintf(id_num,20,"%llu",last_insert_id);

    int len = strlen(id_num);
    send_buf->data[send_buf->size] = (unsigned char) ((len >> 0) & 0xFF);
    send_buf->size++;
    if(0 != byte_array_append_len(send_buf, id_num, len)){
        return -1;
    }

	int size = send_buf->size - data_begin - 4;

    send_buf->data[data_begin] = (unsigned char) ((size >> 0) & 0xFF);
    send_buf->data[data_begin + 1] = (unsigned char) ((size >> 8) & 0xFF);
    send_buf->data[data_begin + 2] = (unsigned char) ((size >> 16) & 0xFF);
    send_buf->data[data_begin + 3] = (unsigned char) ((packet_num >> 0) & 0xFF);

    return 0;
}

int make_last_insert_id_packet(network_socket *s, int is_execute) {

    if(0 != byte_array_append_len(s->send_buf, "\x01\x00\x00\x01\x01", 5)){
        return -1;
    }
    int packet_num = 2;

	static const unsigned char last_insert_id[] = "\x03mpl" //catalog
		"\x03mpl" //db
		"\x03mpl" //table
		"\x03mpl" //org_table
		"\x10last_insert_id()" //name
		"\x10last_insert_id()" //org_name
		"\x0c\x1c\x00\x15\x00\x00\x00\x08\x81\x00\x00\x00\x00";

	make_field_packet(s->send_buf, packet_num, last_insert_id,
			sizeof(last_insert_id) - 1);
	packet_num++;

	make_eof_pakcet(s->send_buf, packet_num);
	packet_num++;


	if(is_execute == 0) {
		make_raw_data_last_insert_id(s->send_buf,packet_num,s->last_insert_id);
	} else {
		make_execute_raw_data_last_insert_id(s->send_buf,packet_num,s->last_insert_id);
	}
	packet_num++;

	make_eof_pakcet(s->send_buf, packet_num);
	packet_num++;

	return 0;
}

inline int make_proxy_status_result_packet(network_socket *s, int type) {
    int packet_num = 1;
    make_result_set_header_packet(s->send_buf, type, packet_num);
    packet_num++;

    int i;
    int j = 0;
    int total_num;
    static const unsigned char user_ip[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x07User#IP" //name
                "\x07User#IP" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";
   static const unsigned char dbproxy_conn_field[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x09Proxy_NUM" //name
                "\x09Proxy_NUM" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char db_conn_field[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x06"
                "DB_NUM" //name
                "\x06"
                "DB_NUM" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char master_field[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x06Master" //name
                "\x06Master" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char slave_field[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x05Slave" //name
                "\x05Slave" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";
   static const unsigned char db_user_ip_field[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x0a"
                "DB#User#IP" //name
                "\x0a"
                "DB#User#IP" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";
   static const unsigned char user_conn_num[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x08User_NUM" //name
                "\x08User_NUM" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

  static const unsigned char vm_size[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x06"
                "Vmsize" //name
                "\x06"
                "Vmsize" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char conn_pool_size[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x0e"
                "Conn_Pool_Size" //name
                "\x0e"
                "Conn_Pool_Size" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char sock_pool_size[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x0e"
                "Sock_Pool_Size" //name
                "\x0e"
                "Sock_Pool_Size" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char cur_time[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x04"
                "Time" //name
                "\x04"
                "Time" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   static const unsigned char pid[] = "\x03mpl" //catalog
                "\x03mpl" //db
                "\x03mpl" //table
                "\x03mpl" //org_table
                "\x03"
                "Pid" //name
                "\x03"
                "Pid" //org_name
                "\x0c\x1c\x00\xc8\x00\x00\x00\xfd\x00\x00\x00\x00\x00";

   status_mmap_flag *s4 = NULL;
    switch (type) {
    case 1:

        make_field_packet(s->send_buf, packet_num, pid,
                sizeof(pid) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, user_ip, sizeof(user_ip) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, dbproxy_conn_field,
                sizeof(dbproxy_conn_field) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, db_conn_field,
                sizeof(db_conn_field) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, master_field,
                sizeof(master_field) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, slave_field,
                sizeof(slave_field) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, cur_time,
                sizeof(cur_time) - 1);
        packet_num++;

        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;

        total_num = CONFIG_STATUS_MAX_PRODUCTUSER_NUM
                * CONFIG_STATUS_MAX_IP_NUM ;
        status_user_and_ip *t1 = NULL;

        for(i = 0; i < s->srv->config->max_threads; i++){
            t1 = s->srv->s1 + CONFIG_STATUS_MAX_PRODUCTUSER_NUM
                    * CONFIG_STATUS_MAX_IP_NUM * i;
            s4 = s->srv->s4 + i;

            for (j = 0; j < total_num; j++) {
                if (t1->is_used != s4->mmap_flag) {
                    break;
                }
                make_raw_data_type1(s->send_buf, packet_num, t1);
                packet_num++;
                t1 += 1;
            }
        }


        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;

        return 0;

    case 2:

        make_field_packet(s->send_buf, packet_num, pid,
                sizeof(pid) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, db_user_ip_field,
                sizeof(db_user_ip_field) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, user_conn_num,
                sizeof(user_conn_num) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, cur_time,
                sizeof(cur_time) - 1);
        packet_num++;

        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;

       total_num = CONFIG_STATUS_MAX_PRODUCTUSER_NUM
                * CONFIG_STATUS_MAX_IP_NUM * CONFIG_STATUS_MAX_DB_NUM;

        status_dbip_and_user *t2 = NULL;

        for(i = 0; i < s->srv->config->max_threads; i++){
            t2 = s->srv->s2 + CONFIG_STATUS_MAX_PRODUCTUSER_NUM
                * CONFIG_STATUS_MAX_IP_NUM * CONFIG_STATUS_MAX_DB_NUM
                *  i;

            s4 = s->srv->s4 + i;

            for (j = 0; j < total_num; j++) {
                if (t2->is_used != s4->mmap_flag) {
                    break;
                }
                make_raw_data_type2(s->send_buf, packet_num, t2);
                packet_num++;
                t2 += 1;
            }

        }

        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;
        return 0;

    case 3:
        make_field_packet(s->send_buf, packet_num,pid,
                sizeof(pid) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num,vm_size,
                sizeof(vm_size) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, conn_pool_size,
                sizeof(conn_pool_size) - 1);
        packet_num++;

        make_field_packet(s->send_buf, packet_num, sock_pool_size,
                sizeof(sock_pool_size) - 1);
        packet_num++;


        make_field_packet(s->send_buf, packet_num, cur_time,
                sizeof(cur_time) - 1);
        packet_num++;

        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;

        total_num = s->srv->config->max_threads;

        status_mysql_proxy_layer *t3 = s->srv->s3;
        for (i = 0; i < total_num; i++) {
            make_raw_data_type3(s->send_buf, packet_num, t3);
            packet_num++;
            t3 += 1;
        }
        make_eof_pakcet(s->send_buf, packet_num);
        packet_num++;
        return 0;
    default:
        return -1;
    }

}

inline int packet_query_copy(packet_query *src, packet_query *dest) {
    if (src == NULL || dest == NULL) {
        log_error(logger, "src query or dest query is null");
        return -1;
    }
    if (dest->args_calloc_len < src->args_len) {
        int acc_alloc = 1;
        while (acc_alloc < src->args_len)
            acc_alloc <<= 1;
        void *p;
        if (NULL == (p = malloc(acc_alloc))) {
            return -1;
        }
        if (dest->args_calloc_len > 0){
            free(dest->args);
            dest->args = NULL;
        }
        dest->args = p;
        dest->args_calloc_len = acc_alloc;
    }
    dest->args_len = src->args_len;
    dest->command = src->command;
    dest->type = src->type;
    memcpy(dest->args, src->args, src->args_len);
    dest->is_designated_db = src->is_designated_db;
    memcpy(dest->designated_db_ip, src->designated_db_ip, MAX_IP_LEN);
    dest->designated_port = src->designated_port;
    dest->designated_type = src->designated_type;

    dest->qtype = src->qtype;
    dest->statement_id = src->statement_id;
	dest->is_last_insert_id = src->is_last_insert_id;
    return 0;
}
inline int packet_result_copy(packet_result *src, packet_result *dest) {
    if (src == NULL || dest == NULL) {
        log_error(logger, "src result or dest result is null");
        return -1;
    }

    src->column_cnt = dest->column_cnt;
    src->is_already_read = dest->is_already_read;
    src->param_cnt = dest->param_cnt;
    src->qstatus = dest->qstatus;
    src->ret_column_cnt = dest->ret_column_cnt;
    src->state = dest->state;
    src->init_size = dest->init_size;

    return 0;

}

int network_socket_reset(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s == NULL");
        return -1;
    }
    if (s->fd > 0)
        close(s->fd);
    s->fd = -1;
    s->packet_len = -1;
    s->packet_read_len = 0;
    s->is_clean = 1;
    s->ms = MS_UNKNOWN;
    s->port = -1;
    s->query_times = 0;
    s->state = STATE_INIT;
    s->is_client_socket = 0;
    s->packet_id = 0;
    s->query.status = QUERY_UNUSING;
    s->send_buf_offset = 0;
    s->db = NULL;
    s->start_time.tv_sec = 0;
    s->start_time.tv_usec = 0;
    s->end_time.tv_sec = 0;
    s->end_time.tv_usec = 0;
    s->header_read_len = 0;
    s->header_offset = 0;
    s->ip[0] = '\0';
    s->served_client_times = 0;
    s->is_query_send_partly = 0;
    s->is_auth_result_send_partly = 0;
    s->is_handshake_send_partly = 0;
    s->is_auth_result_send_partly = 0;
    s->has_call_sql = 0;
    s->has_set_sql = 0;
    s->has_use_sql = 0;
    s->has_changeuser_sql = 0;
    s->prepare_cnt = 0;
    byte_array_clear(s->self_buf);
    byte_array_clear(s->send_buf);
    s->client = NULL;
    s->server = NULL;
    s->is_exec_last_use_query = 0;
    s->p_user = NULL;
    s->current_db[0] = '\0';
    s->dbip_and_user_and_userip[0] = '\0';

    s->cache_cmd_index = 0;
	while(s->cache_cmds->len > 0) {
		packet_query* q = g_ptr_array_remove_index(s->cache_cmds,s->cache_cmds->len - 1);
		if(q != NULL) {
			if(q->args != NULL) {
				free(q->args);
			}
			free(q);
		}
	}
	g_ptr_array_free(s->cache_cmds, 1);
	if (NULL == (s->cache_cmds = g_ptr_array_new())) {
		log_error(logger,"create s->cache_cmds using g_ptr_array_new() failed");
		return -1;
    }

    
    s->is_authed = 0;
    s->is_check_ip = 0;
    s->is_sending_cache_cmds = 0;
    s->is_transaction = 0;
    s->is_using_db = 0;
    s->key_type1 = 0;
    s->key_type2 = 0;
    s->username_and_ip[0] = '\0';
    s->write_time.tv_sec = 0;
    s->write_time.tv_usec = 0;
    s->query.is_designated_db = 0;
    s->query.designated_type = 0;
    s->query.args_len = 0;
    s->query.is_proxy_status = 0;
    s->is_in_pool = 0;
    s->is_designated = 0;
    s->cache_cmd = 0;

   // s->is_cache_send_done = 0;
    s->session_key = 0;

    s->has_prepare_sql = 0;

    int is_failed = 0;
    if(s->prepare_read_array->len > 0) {
        g_array_free(s->prepare_read_array,TRUE);

        if(NULL == (s->prepare_read_array = g_array_new(FALSE, FALSE, sizeof(int)))) {
           log_warning(logger,"create prepare read array using g_array_new() failed");
           is_failed = 1;
        }
    }

    if(s->prepare_write_array->len > 0) {
        g_array_free(s->prepare_write_array,TRUE);

        if(NULL == (s->prepare_write_array = g_array_new(FALSE, FALSE, sizeof(int)))) {
           log_warning(logger,"create prepare write array using g_array_new() failed");
           is_failed = 1;
        }
    }

	if(s->last_insert_id_array->len > 0) {
        g_array_free(s->last_insert_id_array,TRUE);

        if(NULL == (s->last_insert_id_array = g_array_new(FALSE, FALSE, sizeof(int)))) {
           log_warning(logger,"create last_insert_id_array using g_array_new() failed");
           is_failed = 1;
        }
    }

	if(NULL != s->prepare_statement_ids){
		while(s->prepare_statement_ids->len > 0) {
			char* port_id = g_ptr_array_remove_index(s->prepare_statement_ids,s->prepare_statement_ids->len - 1);
			if(port_id != NULL) {
				free(port_id);
			}
		}
		g_ptr_array_free(s->prepare_statement_ids,1);
	}

	if(NULL == (s->prepare_statement_ids = g_ptr_array_new())) {
		log_warning(logger,"create prepare statement id using g_ptr_array_new() failed");
		is_failed = 1;
	}

	if(is_failed == 1) {
		return -1;
	}

    s->statement_id = 0;

    s->query.qtype = -1;
    s->query.statement_id = -1;

	s->is_auth_failed = 0;
	/*s->query_processed_num = 0;*/

	s->last_insert_id = 0;

	s->query.is_last_insert_id = 0;

	s->is_execute_last_insert_id = 0;

	s->client_found_rows = 0;

	s->client_ignore_space = 0;
        s->loading_data=0;
        s->is_during_err=0;
        bzero(&(s->result), sizeof(s->result));

    return 0;

}
int network_socket_pool_add(network_socket_pool *pool, network_socket *s) {
    if (NULL == pool || NULL == s) {
        log_error(logger, "pool == NULL || NULL == s");
        return -1;
    }
    if(-1 == network_socket_reset(s)){
        network_socket_free(s);
        return -1;
    }
    g_queue_push_tail(pool->sockets, s);
    return 0;
}

inline int network_socket_put_back(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "put back network_socket failed, s is null");
        return -1;
    }

    if (s->is_client_socket == 1 && s->srv != NULL) {
		s->end_time = s->srv->cur_time;
		if(s->server != NULL)
			log_work(logger, s, LOG_WORK_TYPE_QUIT);
	}

    if (s->use_times > NETWORK_SOCKET_MAX_USE_TIMES ) {
        log_load(logger, "network_socket s->fd=%d s->is_client=%d use times=%d > NETWORK_SOCKET_MAX_USE_TIMES=%d, going to free",
                s->fd, s->is_client_socket, s->use_times, NETWORK_SOCKET_MAX_USE_TIMES);
        network_socket_free(s);
    } else {

		if(s->srv == NULL) {
            network_socket_free(s);
		} else {
			if (0 != network_socket_pool_add(s->srv->sockets_pool, s)) {
				log_warning(logger, "network_socket_pool_add failed, s->fd=%d",
						s->fd);
				network_socket_free(s);
			}
		}

	}
	return 0;
}
inline int start_trim_from_left(unsigned char *p, int args_len) {
    int cnt = 0;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\x0B') {
        args_len--;
        cnt++;
        if (args_len <= 0) {
            return cnt;
        }
        p++;
    }
    return cnt;
}
inline void network_socket_free(network_socket *s) {

    if (NULL == s)
        return;
    if (s->fd > 0)
        close(s->fd);
    s->fd = -1;
    if (NULL != s->self_buf)
        byte_array_free(s->self_buf);
    if (NULL != s->send_buf)
        byte_array_free(s->send_buf);
    if (s->query.args_calloc_len > 0){
        free(s->query.args);
        s->query.args = NULL;
    }
  
    if(NULL != s->cache_cmds){
		while(s->cache_cmds->len > 0) {
			packet_query* q = g_ptr_array_remove_index(s->cache_cmds,s->cache_cmds->len - 1);
			if(q != NULL) {
				if(q->args != NULL) {
					free(q->args);
				}
				free(q);
			}
		}
        g_ptr_array_free(s->cache_cmds,1);
    }

    if(s->prepare_read_array->len > 0) {
        g_array_free(s->prepare_read_array,TRUE);
     }

    if(s->prepare_write_array->len > 0) {
        g_array_free(s->prepare_write_array,TRUE);
    }

	if(s->last_insert_id_array->len > 0) {
        g_array_free(s->last_insert_id_array,TRUE);
    }

	if(NULL != s->prepare_statement_ids){
		while(s->prepare_statement_ids->len > 0) {
			char* port_id = g_ptr_array_remove_index(s->prepare_statement_ids,s->prepare_statement_ids->len - 1);
			if(port_id != NULL) {
				free(port_id);
			}
		}
		g_ptr_array_free(s->prepare_statement_ids,1);
	}
	free(s);
	s = NULL;
}

inline int protocol_get_byte_len(unsigned char *packet, guint *off,
        packet_query *query) {
    if (NULL == packet || NULL == off || NULL == query) {
        log_error(logger, "NULL == packet || NULL == off || NULL == query");
        return RET_ERROR;
    }

    query->args_len++;
    int calloc_len = query->args_len;

    unsigned char *bytes;
    if (query->args_calloc_len < query->args_len) {
        if (query->args_calloc_len > 0) {
            free(query->args);
            query->args = NULL;
            query->args_calloc_len = 0;
            query->args_len = 0;
        }
        if (NULL == (bytes = malloc(calloc_len))) {
            log_error(logger, "malloc memory failed, need %d bytes, no enough memory", calloc_len);
            return RET_ERROR;
        }
        query->args = bytes;
        query->args_calloc_len = calloc_len;
        query->args_len = calloc_len;
    }
    memcpy(query->args, packet + *off, query->args_len - 1);
    *off += query->args_len - 1;
    *(query->args + query->args_len - 1) = '\x00';

    return RET_SUCCESS;
}
inline int protocol_get_statement_id(network_socket *s, unsigned char *data,
        guint *off, gsize len, int *result) {
    if (NULL == s || NULL == data || NULL == off || len <= 0 || NULL == result) {
        log_error(logger, "s == NULL || data==NULL || NULL == off || len=%d <= 0 || result==NULL", len);
        return RET_ERROR;
    }
    if (s->packet_len + PACKET_HEADER_LEN < *off + len) {
        log_error(logger, "s->packet_len=%d + PACKET_HEADER_LEN=%d < off=%d + len=%d", s->packet_len, PACKET_HEADER_LEN, *off, len);
        return RET_ERROR;
    }
    int i;
    int ret_int = 0;
    for (i = 0; i < len; i++) {
        ret_int += (unsigned char) data[*off + i] << i * 8;
    }
    *off += len;
    *result = ret_int;
    return RET_SUCCESS;
}
inline int protocol_get_int_len(network_socket *s, unsigned char *data,
        guint *off, gsize len, guint64 *result) {
    if (NULL == s || NULL == data || NULL == off || len <= 0 || NULL == result) {
        log_error(logger, "s == NULL || data==NULL || NULL == off || len=%d <= 0 || result==NULL", len);
        return RET_ERROR;
    }
    if (s->packet_len + PACKET_HEADER_LEN < *off + len) {
        log_error(logger, "s->packet_len=%d + PACKET_HEADER_LEN=%d < off=%d + len=%d", s->packet_len, PACKET_HEADER_LEN, *off, len);
        return RET_ERROR;
    }
    int i;
    guint64 ret_int = 0;
    for (i = 0; i < len; i++) {
        ret_int += (unsigned char) data[*off + i] << i * 8;
    }
    *off += len;
    *result = ret_int;
    return RET_SUCCESS;
}
inline int protocol_get_string(unsigned char *data, int size, guint *off,
        char *ret_str, int capacity) {

    if (NULL == data || NULL == off) {
        log_error(logger, "data==NULL || NULL == off");
        return -1;
    }

    int len;
    for (len = 0; *off + len < size && *(data + *off + len) != '\0'; len++)
        ;
    if (*off + len >= size) {
        log_warning(logger, "protocol_get_string doesn't have \\0 char");
        return -1;
    }
    if (len > 0) {
        if (ret_str != NULL) {
            if (len + 1 > capacity)
                return -1;
            memcpy(ret_str, data + *off, len);
            *(ret_str + len) = '\0';
        }
    } else {
        return -1;
    }
    *off += len + 1;
    return 0;
}

inline int real_read(network_socket *s, byte_array *send_buf, int we_want,
        int *ret_read_len) {

    if (NULL == s || NULL == send_buf || NULL == ret_read_len) {
        log_error(logger, "s == NULL || send_buf == NULL || NULL == ret_read_len");
        return RET_ERROR;
    }
    int ret;
    if (we_want <= 0) {
        *ret_read_len = 0;
        ret = RET_SUCCESS;
        goto return_step;
    }
    if ((send_buf->capacity - send_buf->size) < we_want) {
        ret = byte_array_append_size(send_buf, we_want - send_buf->capacity
                + send_buf->size, 0);
        if (ret != RET_SUCCESS)
            goto return_step;
    }
    int len = 0;
    len = read(s->fd, send_buf->data + send_buf->size, we_want);
    *ret_read_len = len >= 0 ? len : 0;
    send_buf->size += *ret_read_len;
    if (len == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            ret = RET_WAIT_FOR_EVENT;
            goto return_step;
        } else {
            ret = RET_SHUTDOWN;
            goto return_step;
        }
    } else if (len == 0) {
        ret = RET_SHUTDOWN;
        goto return_step;
    }
    if (len < we_want) {
        ret = RET_WAIT_FOR_EVENT;
        goto return_step;
    }

    ret = RET_SUCCESS;
    return_step: return ret;
}

inline int read_packet(network_socket *s, byte_array *send_buf) {

    if (NULL == s || send_buf == NULL) {
        log_error(logger, "s == NULL || send_buf == NULL");
        return RET_ERROR;
    }

    int ret;
    int read_len = 0;
    if (4 != s->header_read_len) {
        ret = real_read(s, send_buf, PACKET_HEADER_LEN - s->header_read_len,
                &read_len);
        s->header_read_len += read_len;
        if (ret != RET_SUCCESS) {
            goto return_step;
        } else if (s->header_read_len < 4) {
            ret = RET_WAIT_FOR_EVENT;
            goto return_step;
        }
        unsigned char *header;
        s->header_offset = send_buf->size - 4;
        header = send_buf->data + s->header_offset;
        s->packet_len = header[0] | header[1] << 8 | header[2] << 16;
		if(s->is_client_socket == 0 && s->client != NULL)
			s->client->result.result_set_size += s->packet_len;
        s->packet_id = header[3];
        if (s->packet_len > PACKET_LEN_MAX) { // check packet_len_max
            log_warning(logger, "packet_len=%d > PACKET_LEN_MAX=%d", s->packet_len, PACKET_LEN_MAX);
            ret = RET_ERROR;
            goto return_step;
        }
    }
    read_len = 0;
    ret = real_read(s, send_buf, s->packet_len - s->packet_read_len, &read_len);
    s->packet_read_len += read_len;
    if (ret != RET_SUCCESS) {
        goto return_step;
    } else if (s->packet_len > s->packet_read_len) {
        ret = RET_WAIT_FOR_EVENT;
        goto return_step;
    }
    s->packet_read_len = 0;
    s->header_read_len = 0;
    ret = RET_SUCCESS;

    return_step: return ret;
}

inline int set_fd_flags(int fd) {

    if (fd < 0) {
        return -1;
    }
    int opts;
    if (0 > (opts = fcntl(fd, F_GETFL))) {
        log_error(logger, "set_fd_flags() fd=%d fcntl(fd, F_GETFL) error", fd);
        return -1;
    }
    opts = opts | O_NONBLOCK;
    if (0 > fcntl(fd, F_SETFL, opts)) {
        log_error(logger, "set_fd_flags() fd=%d fcntl(fd, F_SETFL, opts) error", fd);
        return -1;
    }
    struct linger li;
    memset(&li, 0, sizeof(li));
    li.l_onoff = 1;
    li.l_linger = 0;

    int ret;
    if (0 != (ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, (const char*) &li,
            sizeof(li)))) {
        log_error(logger, "set_fd_flags() fd=%d setsockopt linger error", fd);
        return -1;
    }
    int var = 1;
    if (0
            != (ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &var,
                    sizeof(var)))) {
        log_error(logger, "set_fd_flags() fd=%d setsockopt tcp_nodelay error", fd);
        return -1;
    }
    return ret;
}
int network_socket_buf_reset(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s == NULL");
        return -1;
    }
    byte_array_clear(s->self_buf);
    byte_array_clear(s->send_buf);
	return 1;
}
inline network_socket* network_socket_create() {

	network_socket *s = NULL;
	if (NULL == (s = calloc(1, sizeof(network_socket))) || NULL == (s->send_buf
				= byte_array_sized_new(SEND_BUF_DEFAULT_SIZE)) || NULL
			== (s->self_buf = byte_array_sized_new(SELF_BUF_DEFAULT_SIZE))
			|| NULL == (s->cache_cmds = g_ptr_array_new()) || NULL
			== (s->prepare_read_array = g_array_new(FALSE, FALSE, sizeof(int)))
			|| NULL == (s->prepare_write_array = g_array_new(FALSE, FALSE,
					sizeof(int))) || NULL == (s->last_insert_id_array = g_array_new(FALSE, FALSE,
					sizeof(int)))|| NULL == (s->prepare_statement_ids
				= g_ptr_array_new())) {
		log_error(logger, "network_socket_create() failed not enough memory");
		network_socket_free(s);
		return NULL;
	}
    s->fd = -1;
    s->packet_len = -1;
    s->is_clean = 1;
    s->ms = MS_UNKNOWN;
    s->port = -1;

    s->statement_id = 0;

    s->query.qtype = -1;
    s->query.statement_id = -1;
	s->query_processed_num = 0;

    return s;
}

inline int connect_nonblock(int fd, struct sockaddr * addr, size_t len,
        int u_seconds) {

    if (NULL == addr) {
        log_error(logger, "sockaddr == NULL");
        return -1;
    }
    if (0 > set_fd_flags(fd)) {
        log_error(logger, "fd=%d set_fg_flags failed, errno=%d, error:%s", fd, errno, strerror(errno));
        return -1;
    }
    if (0 != connect(fd, addr, len)) {
        if (errno != EINPROGRESS) {
            log_warning(logger, "connect failed, errno=%d, error:%s", errno, strerror(errno));
            return -1;
        }
    } else {
        return 0;
    }
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    wset = rset;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = u_seconds;

    int n;
    if (0 == (n = select(fd + 1, &rset, &wset, NULL, &timeout))) {
        log_warning(logger, "connect_nonblock %d us timeout", u_seconds);
        return -1;
    } else if (n < 0) {
        log_warning(logger, "connect_nonblock error return=%d, errno=%d, error:%s", n, errno, strerror(errno));
        return -1;
    }
    int error;
    socklen_t e_len;
    if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
        e_len = sizeof(error);
        if (0 > getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &e_len)) {
            log_warning(logger, "connect_nonblock FD_ISSET=true getsockopt < 0");
            return -1;
        }
        if (error) {
            close(fd);
            log_warning(logger, "connect_nonblock FD_ISSET=true error=%d, %s", error, strerror(errno));
            return -1;
        }
    } else {
        log_warning(logger, "connect_nonblock FD_ISSET empty");
        return -1;
    }
    return 0;
}

network_socket* create_listen_network_socket(network_server *srv) {

    if (NULL == srv) {
        log_error(logger, "srv==NULL");
        return NULL;
    }
    network_socket *s;
    if (NULL == (s = network_socket_get(srv->sockets_pool, 1))) {
        log_error(logger, "network_socket_get(srv->sockets_pool, 1) return null");
        return NULL;
    }
    int val = 1;
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(srv->config->port);

    if (0 > bind(s->fd, (struct sockaddr *) &listen_addr, sizeof(listen_addr))) {
        log_error(logger, "bind() errno=%d, error=%s", errno, strerror(errno));
        return NULL;
    }
    if (0 > listen(s->fd, srv->config->backlog)) {
        log_error(logger, "listen() failed, fd=%d, bakclog=%d, errno=%d, error:%s",
                s->fd, srv->config->backlog, errno, strerror(errno));
        return NULL;
    }
    if (0 > set_fd_flags(s->fd)) {
        return NULL;
    }
    srv->listen_socket = s;
    return s;
}
inline network_socket* connect_to_server_cmp(GPtrArray *dbs, int is_cmp,
        network_socket *client) {

    network_database *cur_db = NULL;
    network_socket *server = NULL;
    int dbs_len = dbs->len;
    if (client->p_user->d_user == NULL) {
        log_warning(logger,"client->p_user %s ->d_user is NULL",client->p_user->username);
        return NULL;
    }
    int i;
    for (i = 0; i < dbs_len; i++) {
        cur_db = g_ptr_array_index(dbs, i);

        if(client->ms == MS_MASTER){
            if (cur_db->is_old != cur_db->clus->w_update_flag)
                continue;
        }else{
            if (cur_db->is_old != cur_db->clus->r_update_flag)
                continue;
        }

        if (is_cmp == 1 && (0 != strncmp(cur_db->addr.addr_name,
                client->query.designated_db_ip, 20) || cur_db->addr.port
                != client->query.designated_port)) {
            continue;
        }

        if (cur_db->cur_connected >= (cur_db->max_connections
                / client->srv->config->max_threads))
            continue;


        if ((client->srv->cur_time.tv_sec - cur_db->last_fail_time)
                < cur_db->time_reconnect_interval) {
            continue;
        }

        //失败重连
        int j;
        int reconnect_times = client->srv->config->reconnect_times;
        for (j = 0; j < reconnect_times; j++) {
            if (NULL == (server = network_socket_get(client->srv->sockets_pool, 1))) {
                return NULL;
            }
            if (0 != connect_nonblock(server->fd,
                    (struct sockaddr *) &cur_db->addr.addr_ip,
                    cur_db->addr.addr_len, cur_db->connect_timeout)) {
                log_warning(logger, "can't connect to %s:%d, errno=%d, error:%s, maybe mysqld hasn't been started reconnect time=%d", cur_db->addr.addr_name, cur_db->addr.port, errno, strerror(errno), i);
                network_socket_put_back(server);
                continue;
            }
            cur_db->cur_connected++;
            cur_db->last_fail_time = 0;
            server->db = cur_db;
            client->db = cur_db;
            //			server->ms = client->ms;

            server->state = STATE_CONNECTED_SERVER;
            break;
        }
        if (j == reconnect_times) {
            cur_db->last_fail_time = client->srv->cur_time.tv_sec;
            continue;
        } else {

            server->p_user = client->p_user;

            if (server->fd < 0 || server->fd >= CONFIG_MPL_EPOLL_MAX_SIZE) {
                log_warning(logger, "server->fd=%d < 0 || >= CONFIG_MPL_EPOLL_MAX_SIZE=%d", server->fd, CONFIG_MPL_EPOLL_MAX_SIZE);
                server_free(server, 0);
                continue;
            }
            client->srv->poll->fd_mapping[server->fd] = server;
            poll_events_add(client->srv->poll, server, EPOLLIN);
            server->srv = client->srv;
            server->poll = client->srv->poll;
            server->last_active_time = client->srv->cur_time.tv_sec;
            server->served_client_times = 1;
            return server;
        }

    }

    return NULL;
}

inline network_socket* get_network_socket_from_queue(GQueue *queue, int is_cmp,
        char *ip, int port) {
    int queue_len = queue->length;
    if (queue_len == 0)
        return NULL;
    network_socket *db_conn;
    if (is_cmp == 1) {
        int i;
        for (i = 0; i < queue_len; i++) {
            db_conn = (network_socket*) g_queue_peek_nth(queue, i);
            if (0 == strncmp(db_conn->db->addr.addr_name, ip, MAX_IP_LEN)
                    && db_conn->db->addr.port == port) {
                g_queue_pop_nth(queue, i);
                db_conn->is_in_pool = 0;
                return db_conn;
            }
        }
        //if (i == queue_len) {
            return NULL;
        //}
    } else {
        db_conn = g_queue_pop_head(queue);
        db_conn->is_in_pool = 0;
        return db_conn;
    }
}

inline int copy_server_connection(network_socket *src_socket,
        network_socket *des_socket) {

    des_socket->is_client_socket = src_socket->is_client_socket;
    des_socket->ms = src_socket->ms;
    des_socket->p_user = src_socket->p_user;
    des_socket->srv = src_socket->srv;
    des_socket->client = src_socket->client;
    if (0 != packet_query_copy(&(src_socket->query), &(des_socket->query)))
        return -1;
    return 0;
}
inline void reset_client_sending_cmd_status(network_socket *client) {
    if (client->cache_cmds->len > 0 ) {
        client->is_sending_cache_cmds = 1;
    }
}

void set_new_server_stat(network_socket *new_server,network_socket *client,guint db_key){
    client->db = new_server->db;
    snprintf(new_server->current_db, MAX_DEFAULT_DB_NAME_LEN,"%s", client->current_db);
    new_server->has_call_sql = client->has_call_sql;
    new_server->has_set_sql = client->has_set_sql;
    new_server->has_use_sql = client->has_use_sql;
    new_server->has_changeuser_sql = client->has_changeuser_sql;
    new_server->ms = client->ms;
    new_server->p_user = client->p_user;
    new_server->srv = client->srv;
    new_server->poll = client->poll;
    new_server->is_client_socket = 0;
    new_server->client = client;
    if(client->query.status == QUERY_UNUSING)
        client->query.status = QUERY_SERVER_RESTART;
    client->server = new_server;
    client->db = new_server->db;
    if (db_key != client->db->key ) {
        if (client->ms == MS_MASTER) {
            snprintf(client->dbip_and_user_and_userip, 3, "M:");
        } else {
            snprintf(client->dbip_and_user_and_userip, 3, "S:");
        }
        snprintf(client->dbip_and_user_and_userip + 2,MAX_STATUS_TYPE_2_KEY - 2,"%s#%s#%s",client->db->addr.addr_name,
                client->p_user->username,client->ip);
        client->key_type2 = str_hash(client->dbip_and_user_and_userip);
    }
}

char *get_hash_key(char *buf, int size, int client_found_rows, 
		int client_ignore_space) {
	if (!buf || size <=0 ) {
		return NULL;
	}

	snprintf(buf, size, "$%d$%d", (client_found_rows>0?1:0), 
			(client_ignore_space>0?1:0) );
        buf[4]='\0';
	return buf;
}

network_socket* server_connection_failover(network_socket *server,
        network_socket *client) {
    log_warning(logger,"call server_connection_failover server fd=%d, client fd=%d",server->fd,client->fd);
    network_socket *new_server = NULL;
    GHashTable *db_user_mapping;

    if (server == NULL || client == NULL) {
        log_warning(logger,"server or client is NULL");
        return NULL;
    }
    if (client->p_user->d_user == NULL) {
        log_warning(logger,"client->p_user->d_user is NULl, p_user name=%s",client->p_user->username);
        return NULL;
    }
    if (client->p_user->d_user->is_old != client->srv->config->user_update_flag) {
        server_free(server, 1);
        return NULL;
    }

    guint db_key = 0;
    if (client->db != NULL) {
        db_key = client->db->key;
    }

    if (NULL == (db_user_mapping = g_hash_table_lookup(
            client->p_user->d_user->clus->db_conn_pools,
            client->p_user->d_user->username))) {
        log_warning(logger,"no conn_pool for d_user name %s existed",client->p_user->d_user->username);
        server_free(server, 1);
        return NULL;
    }
	char tmp_buf[5];
    conn_pool_queue *q = g_hash_table_lookup(db_user_mapping,
            get_hash_key(tmp_buf, 5, client->client_found_rows, client->client_ignore_space) );

    if (NULL != q) {
        //先从连接池中取连接
        if (server->ms == MS_MASTER) {
            new_server = get_network_socket_from_queue(q->w_queue, 0, NULL, 0);
            if (new_server != NULL) {
//                server->db->last_fail_time = client->srv->cur_time.tv_sec;
//                server->db->last_fail_time = 0;
                server_free(server, 0);
                reset_client_sending_cmd_status(client);
                set_new_server_stat(new_server,client,db_key);
                return new_server;
            }
        } else if (server->ms == MS_SLAVE) {
            new_server = get_network_socket_from_queue(q->r_queue, 0, NULL, 0);
            if (new_server != NULL) {
//                server->db->last_fail_time = client->srv->cur_time.tv_sec;
//                server->db->last_fail_time = 0;
                server_free(server, 0);
                reset_client_sending_cmd_status(client);
                set_new_server_stat(new_server,client,db_key);
                return new_server;
            }
        } else {
            server_free(server, 1);
            return NULL;
        }
    }

    //从连接池中取不到连接，重新建立到数据库到连接
    GPtrArray *dbs = NULL;
    if (server->ms == MS_MASTER)
        dbs = client->p_user->d_user->clus->master_dbs;
    else if (server->ms == MS_SLAVE)
        dbs = client->p_user->d_user->clus->slave_dbs;
    else
        return NULL;

//    server->db->last_fail_time = client->srv->cur_time.tv_sec;
    new_server = connect_to_server_cmp(dbs, 0, client);
    if (new_server != NULL) {

//        server->db->last_fail_time = 0;
        server_free(server, 0);
        reset_client_sending_cmd_status(client);
        set_new_server_stat(new_server,client,db_key);
        return new_server;
    } else {
        server_free(server, 1);
    }

    return NULL;
}
inline int fill_ok_packet(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    const unsigned char packet_ok[] = "\x00\x00\x00"
        "\x02"
        "\x00\x00\x00";
    return network_queue_send_append(s->send_buf, packet_ok, (sizeof(packet_ok)
            - 1), 1, 0);
}

int real_write(network_socket *s) {

    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    int ret = RET_ERROR;

    int we_want = s->send_buf->size - s->send_buf_offset;
    int is_cork = 0;
    if (we_want > 20000) {
        int var = 1;
        if (0 != setsockopt(s->fd, IPPROTO_TCP, TCP_CORK, &var, sizeof(var))) {
            log_warning(logger, "setsockopt fd=%d TCP_CORK failed, errno=%d, error: %s", s->fd, errno, strerror(errno));
        } else {
            is_cork = 1;
        }
    }
    int len;
    if (we_want <= 0) {
        ret = RET_SUCCESS;
        goto return_step;
    }
    if (0 < (len
            = write(s->fd, s->send_buf->data + s->send_buf_offset, we_want))) {
        s->send_buf_offset += len;
    }
    if (len == 0) {
        ret = RET_SHUTDOWN;
        goto return_step;
    } else if (len < 0) {
        switch (errno) {
        case EAGAIN:
            ret = RET_WAIT_FOR_EVENT;
            goto return_step;
        case EINTR:
            ret = RET_WAIT_FOR_EVENT;
            goto return_step;
        default:
            ret = RET_SHUTDOWN;
            goto return_step;
        }
    }
    if (len < we_want) {
        ret = RET_WAIT_FOR_EVENT;
        goto return_step;
    }
    byte_array_clear(s->send_buf);
    s->send_buf_offset = 0;
    ret = RET_SUCCESS;

    return_step: if (is_cork == 1) {
        int var = 0;
        if (0 != setsockopt(s->fd, IPPROTO_TCP, TCP_CORK, &var, sizeof(var))) {
            log_warning(logger, "setsockopt fd=%d UN_TCP_CORK failed, errno=%d, error: %s", s->fd, errno, strerror(errno));
        }
    }
    return ret;
}

inline int connect_db_error_send(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    const unsigned char packet_error[] = "\xff"
        "\x88\x88"
        "#"
        "88S88"
        "can't connect to db server";
    int ret;
    if (RET_SUCCESS != (ret = network_queue_send_append(s->send_buf,
            packet_error, (sizeof(packet_error) - 1), 1, 0))) {
        return ret;
    }
	return real_write(s);
}

//add by ybx
inline int is_not_repeatable(int type)
{
      if(type == SQL_USE_NUM ||type == SQL_USE_IN_QUERY_NUM || type == SQL_SET_NAMES_NUM 
	  	|| type == SQL_SET_CHARSET_CLIENT_NUM || type == SQL_SET_CHARSET_CONNECTION_NUM 
	  	|| type == SQL_SET_CHARSET_DATABASE_NUM || type == SQL_SET_CHARSET_RESULT_NUM 
	  	|| type == SQL_SET_CHARSET_SERVER_1_NUM || type == SQL_SET_CHARSET_SERVER_NUM 
	  	|| type == SQL_SET_COLLATION_CONNECTION_NUM || type == SQL_SET_COLLATION_DATABASE_NUM 
	  	|| type == SQL_SET_COLLATION_SERVER_1_NUM || type == SQL_SET_COLLATION_SERVER_NUM
	  	|| type == SQL_SET_SQL_MODE_NUM || type == SQL_SET_TRANSACTION_ISOLATION_LEVEL_NUM
	  	|| type == SQL_SET_GLOBAL_CHARSET_CLIENT_NUM || type == SQL_SET_GLOBAL_CHARSET_CONNECTION_NUM 
	  	|| type == SQL_SET_GLOBAL_CHARSET_DATABASE_NUM || type == SQL_SET_GLOBAL_CHARSET_RESULT_NUM 
	  	|| type == SQL_SET_GLOBAL_CHARSET_SERVER_1_NUM || type == SQL_SET_GLOBAL_CHARSET_SERVER_NUM 
	  	|| type == SQL_SET_GLOBAL_COLLATION_CONNECTION_NUM || type == SQL_SET_GLOBAL_COLLATION_DATABASE_NUM 
	  	|| type == SQL_SET_GLOBAL_COLLATION_SERVER_1_NUM || type == SQL_SET_GLOBAL_COLLATION_SERVER_NUM
	  	|| type == SQL_SET_GLOBAL_SQL_MODE_NUM || type == SQL_SET_GLOBAL_TRANSACTION_ISOLATION_LEVEL_NUM)
          return 1;
      else
	  return 0;
}
inline int g_ptr_array_no_repeat_add(GPtrArray * array, gpointer data)
{
    int i=0;
    packet_query* cache_query=(packet_query*)data;
    packet_query* cached_query=NULL;
    int to_be_removed[array->len];
    int to_be_removed_num = 0;
    if (data == NULL){
		return 0;
    }
    for(i = 0;i < array->len;i++){
          cached_query= (packet_query*) g_ptr_array_index(array, i);
	   if (cached_query->type == cache_query->type){
	   	if (is_not_repeatable(cached_query->type)){
	   	    to_be_removed[to_be_removed_num]=i;
		    to_be_removed_num++;
	   	}
	   }
	   else
	   {
	         if(cached_query->type == SQL_USE_NUM && cache_query->type == SQL_USE_IN_QUERY_NUM){
		      to_be_removed[to_be_removed_num]=i;
		      to_be_removed_num++;
	         }
	         if(cached_query->type == SQL_USE_IN_QUERY_NUM && cache_query->type == SQL_USE_NUM){
		      to_be_removed[to_be_removed_num]=i;
		      to_be_removed_num++;
	         }
	         
	   }
    }
    /*if (to_be_removed_num > 0){
        for(i = (to_be_removed_num -1);i >= 0;i--){
             packet_query* q=g_ptr_array_remove_index(array, to_be_removed[to_be_removed_num-1]);
	      if(q != NULL) {
	          if(q->args != NULL) {
			free(q->args);
		   }
		   free(q);
	     }
        }
    }*/
    if (to_be_removed_num > 0){
        if (to_be_removed_num > 1)
        	log_warning(logger, "there are too many repeat value in cache cmd %d", to_be_removed_num);
        packet_query* q=g_ptr_array_remove_index(array, to_be_removed[to_be_removed_num-1]);
        if(q != NULL) {
        	if(q->args != NULL) {
        		free(q->args);
        	}
        	free(q);
        }
    }
    g_ptr_array_add(array, data);
    for(i = 0; i<array->len; i++){
        packet_query* q=(packet_query*)g_ptr_array_index(array,i);
        log_load(logger,"[not_repeat]: query is %s,%d",q->args,q->command);
    }
    return 1;
}

inline int fill_use_packet(network_socket *s, char *data, int len) {
	if (s == NULL || data == NULL || len <= 0) {
		log_error(logger, "s == NULL || data == NULL || len=%d <= 0", len);
		return RET_ERROR;
	}

	packet_query* cache_query = NULL;
	cache_query = (packet_query*) calloc(1,sizeof(packet_query));
	if(cache_query == NULL){
		log_error(logger,"calloc memory failed, need %d bytes, no enough memory", sizeof(packet_query));
		return RET_ERROR;
	}

	if (cache_query->args_calloc_len < len) {
		int acc_alloc = 1;
		while (acc_alloc < len)
			acc_alloc <<= 1;
		void *p;
		if (NULL == (p = malloc(acc_alloc))) {
			log_error(logger,"malloc memory failed, need %d bytes, no enough memory", acc_alloc);
			return RET_ERROR;
		}
		if (cache_query->args_calloc_len > 0 && cache_query->args != NULL){
			free(cache_query->args);
			cache_query->args = NULL;
		}
		cache_query->args = p;
		cache_query->args_calloc_len = acc_alloc;
		bzero(cache_query->args,acc_alloc);
	}
	cache_query->args_len = len;
	cache_query->command = 2;
	cache_query->type = SQL_USE_NUM;

	snprintf(cache_query->args,cache_query->args_calloc_len,"%s",data);
	cache_query->is_designated_db = 0;
	cache_query->designated_port = 0;
	cache_query->designated_type = 0;
	cache_query->qtype = 1;
	cache_query->statement_id = 0;
	g_ptr_array_add(s->cache_cmds, cache_query);

	return RET_SUCCESS;
}

inline int fill_string_packet(network_socket *s, char *data, int len) {
	if (s == NULL || data == NULL || len <= 0) {
		log_error(logger, "s == NULL || data == NULL || len=%d <= 0", len);
        return RET_ERROR;
    }
    char *head_info = "\xff\x88\x88#88S88";
    int tmp_len = len + strlen(head_info) + 1;
    char tmp[tmp_len];
    bzero(tmp, tmp_len);

    if (tmp != strncat(tmp, head_info,strlen(head_info))) {
        log_error(logger, "strncat error, head_info=%s", head_info);
        return RET_ERROR;
    }
    if (tmp != strncat(tmp, data, len)) {
        log_error(logger, "strncat error, data=%s", data);
        return RET_ERROR;
    }
    if (RET_SUCCESS != network_queue_send_append(s->send_buf,
            (unsigned char*) tmp, tmp_len, 1, 0)) {
        return RET_ERROR;
    }
    return RET_SUCCESS;
}

inline int fill_auth_failed_packet(network_socket *s, char *data, int len) {
    if (s == NULL || data == NULL || len <= 0) {
        log_error(logger, "s == NULL || data == NULL || len=%d <= 0", len);
        return RET_ERROR;
    }

    byte_array_clear(s->send_buf);

    char *head_info = "\xff\x15\x04#28000";
    int tmp_len = len + strlen(head_info) + 1;
    char tmp[tmp_len];
    bzero(tmp, tmp_len);

    if (tmp != strncat(tmp, head_info,strlen(head_info))) {
    	log_error(logger, "strncat error, head_info=%s", head_info);
        return RET_ERROR;
    }
    if (tmp != strncat(tmp, data, len)) {
    	log_error(logger, "strncat error, data=%s", data);
        return RET_ERROR;
    }
    if (RET_SUCCESS != network_queue_send_append(s->send_buf,
            (unsigned char*) tmp, tmp_len, 2, 0)) {
        return RET_ERROR;
    }
    return RET_SUCCESS;
}

inline int query_result_send(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
/*
 *
 *    if (s->query.is_proxy_status == 1 || (s->query.is_last_insert_id == 1 && s->query.command == '\x03')) {
 *        return real_write(s);
 *
 *    }
 */

    if (s->is_sending_cache_cmds == 1 && s->server != NULL) {
        byte_array_clear(s->send_buf);
        s->send_buf_offset = 0;
		if(s->server->cache_cmd_index == s->cache_cmds->len){
			s->is_sending_cache_cmds = 0;
			s->is_exec_last_use_query = 0;
		}

		return RET_LAST_USE_SUCCESS;
	}
	return real_write(s);
}

extern int query_send(network_socket *s) {

    if (NULL == s || NULL == s->client) {
        log_error(logger, "s==NULL || s->client==NULL");
        return RET_ERROR;
    }
    network_socket *client = s->client;
    packet_query *query = &(client->query);

    //这里处理主从切换时缓存命令的发送
    if (client->is_sending_cache_cmds == 1) {

		while(s->cache_cmd_index < client->cache_cmds->len && client->cache_cmds->len > 0) {

			query = (packet_query*) g_ptr_array_index(
					client->cache_cmds,
					s->cache_cmd_index);

			if(query->qtype == 0 && s->ms == MS_SLAVE) {
				s->cache_cmd_index++;

				if(s->cache_cmd_index >= client->cache_cmds->len) {
					client->is_sending_cache_cmds = 0;
					client->is_exec_last_use_query = 0;
					query = &(client->query);
				}

				continue;
			}
			client->cache_cmd = query->command;
			s->cache_cmd_index++;
			break;
		}
	}


    //穿透命令
    if (client->query.is_designated_db == 1 && client->is_sending_cache_cmds
            == 0) {
        fill_ok_packet(client);
        return RET_SUCCESS;
    }

    if (query->type == SQL_SET_NUM && client->is_sending_cache_cmds == 0) {
        s->cache_cmd_index++;
    }

    //如果是execute等命令，则需要替换statement_id
    if(query->command == '\x17' || query->command == '\x18' || query->command == '\x19' || query->command == '\x1a' || query->command == '\x1c') {
        //这里需要根据命令中的statement id和数据库连接的ip和端口来获取实际的statement id
        int statement_id = 0;

        int i = 0;
        for (i = 0; i < 4; i++) {
            statement_id += (unsigned char) (client->query.args)[i] << i * 8;
        }

        char port_statementid[50];
        if(port_statementid == NULL) {
            log_warning(logger,"can't allocate memory for port and statement id");
            return RET_ERROR;
        }

        snprintf(port_statementid,50,"%d:%d@",statement_id,s->port);

		int real_id = -1;
		for(i = 0; i < client->prepare_statement_ids->len; i++) {
			char* rid = g_ptr_array_index(client->prepare_statement_ids,i);
			if(1 == my_strncasestr(rid,port_statementid,strlen(rid),strlen(port_statementid),1)) {
				char* tid = rid;
				while(*tid != '@'){
					tid += 1;
				}
				tid += 1;
				real_id = atoi(tid);
				break;
			}
		}

        if(real_id != -1) {

            (client->query.args)[0] = (unsigned char)((real_id >> 0) & 0xFF);
            (client->query.args)[1] = (unsigned char)((real_id >> 8) & 0xFF);
            (client->query.args)[2] = (unsigned char)((real_id >> 16) & 0xFF);
            (client->query.args)[3] = (unsigned char)((real_id >> 24) & 0xFF);
        } else {
            log_warning(logger,"can't find statement id");
            return RET_ERROR;
        }


        if(query->command == '\x19'){
            int i = 0;
            packet_query* cache_query = NULL;
            for(i = 0; i < client->cache_cmds->len; i++){
                cache_query = (packet_query*)g_ptr_array_index(client->cache_cmds,i);
                if(cache_query != NULL && cache_query->statement_id == statement_id){
                    break;
                }
            }

            if(i != client->cache_cmds->len){
                cache_query = g_ptr_array_remove_index(client->cache_cmds,i);
                if(cache_query != NULL){
					if(cache_query->args != NULL){
						free(cache_query->args);
						cache_query->args = NULL;
					}
                    free(cache_query);
					cache_query = NULL;
                }


				int j = 0;
				int tid = 0;
				for(j = 0; j < client->prepare_read_array->len; j++){
					tid = g_array_index(client->prepare_read_array,int,j);
					if(tid == statement_id){
						g_array_remove_index(client->prepare_read_array,j);
						break;
					}
				}
				if(j == client->prepare_read_array->len) {
					for(j = 0; j < client->prepare_write_array->len; j++){
						tid = g_array_index(client->prepare_write_array,int,j);
						if(tid == statement_id){
							g_array_remove_index(client->prepare_write_array,j);
							break;
						}
					}
				}
				for(j = 0; j < client->last_insert_id_array->len; j++){
					tid = g_array_index(client->last_insert_id_array,int,j);
					if(tid == statement_id){
						g_array_remove_index(client->last_insert_id_array,j);
						break;
					}
				}

				char temp_id[30];
				memset(temp_id,0,30);
				snprintf(temp_id,30,"%d:",statement_id);

				int i = 0;
				for(i = 0; i < client->prepare_statement_ids->len; i++) {
					char* rid = g_ptr_array_index(client->prepare_statement_ids,i);
					if(1 == my_strncasestr(rid,temp_id,strlen(rid),strlen(temp_id),1)) {
						g_ptr_array_remove_index(client->prepare_statement_ids,i);
						i--;
						free(rid);
					}
				}

			} else {
				log_warning(logger,"can't find prepare query with statement_id %d in the cached cmd array",statement_id);
			}
		}

	}


    network_socket *server = s;
    int ret;
    if (1 == server->is_query_send_partly) {
        ret = real_write(server);
        server->is_query_send_partly = ret == RET_WAIT_FOR_EVENT ? 1 : 0;
        return ret;
    }
    server->ms = client->ms;
    server->packet_id = 0; // packet id check carefully
    int len = query->args_len <= 0 ? 1 : query->args_len;
    if (RET_SUCCESS != (ret = network_queue_send_append(server->send_buf, NULL,
            len, server->packet_id, 1))) {
        return ret;
    }
    if (0 != byte_array_append_len(server->send_buf,
            (const unsigned char *) &(query->command), 1)) {
        return RET_NO_MEMORY;
    }
    if (query->args_len > 1) {
        if (0 != byte_array_append_len(server->send_buf,
                (const unsigned char *) query->args, query->args_len - 1)) {
            return RET_NO_MEMORY;
        }
    } else if (query->args_len == 1) {
        log_error(logger, "query->args_len=1, s->fd=%d server->fd=%d", s->fd, server->fd);
        return RET_ERROR;
    }
    if (query->type == SQL_USE_NUM) {
        server->has_use_sql = 1;
        client->has_use_sql = 1;
    }
    if (RET_WAIT_FOR_EVENT == (ret = real_write(server))) {
        server->is_query_send_partly = 1;
    }
    return ret;
}

//inline int is_need_response(packet_query *query) {
inline int is_need_response(network_socket* client) {
    if(client->is_sending_cache_cmds == 1) {
        if (client->cache_cmd == '\x01' || client->cache_cmd == '\x19' || client->cache_cmd
                == '\x08' || client->cache_cmd == '\x0c' || client->cache_cmd == '\x18') { // make sure no response
            return 0;
        }

    } else {
        if (client->query.command == '\x01' || client->query.command == '\x19' || client->query.command
                == '\x08' || client->query.command == '\x0c' || client->query.command == '\x18') { // make sure no response
            return 0;
        }
    }

    return 1;
}

extern int auth_send(network_server *srv, network_socket *s) {
    if (NULL == srv || NULL == s || NULL == s->client) {
        log_error(logger, "srv == NULL || s == NULL || s->client == NULL");
        return RET_ERROR;
    }
    network_socket *client = s->client;
    network_socket *server = s;

    int ret;
    if (1 == server->is_auth_send_partly) {
        ret = real_write(server);
        s->is_auth_send_partly = ret == RET_WAIT_FOR_EVENT ? 1 : 0;
        return ret;
    }
    db_user *d_user = client->p_user->d_user;
    if (d_user->username[0] == '\0') {
        log_error(logger, "client->p_user->db_user->db_username[0]  is \\0 fd=%d", server->fd);
        return RET_SHUTDOWN;
    }

    byte_array_clear(s->self_buf);

	unsigned char client_flags[] = {0x0d, 0xa2, 0x02, 0};

	if (client->client_found_rows)
	{
		/* Found instead of affected rows */
		client_flags[0] |= 0x2;
	}

	if (client->client_ignore_space)
	{
		/* Ignore spaces before '(' */
		client_flags[1] |= 0x1;
	}

	/* client_flags */
	//log_debug(logger, "client_flags=[%x %x %x %x]", client_flags[0], client_flags[1],
	//			client_flags[2], client_flags[3]);
	if (0 != byte_array_append_len(s->self_buf, client_flags, 4)) {
		return RET_NO_MEMORY;
	}

	/* max_packet_size */
    if (0 != byte_array_append_len(
                    s->self_buf, (const unsigned char *) "\x00\x00\x00\x40", 4)) {
        return RET_NO_MEMORY;
    }

	/* charset_number */
	if (0 != byte_array_append_len(s->self_buf, &d_user->default_charset, 1)) {
		return RET_NO_MEMORY;
	}

	if (0 != byte_array_append_len(
					s->self_buf,
					(const unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 23)) {
		return RET_NO_MEMORY;
	}

    if (0 != byte_array_append_len(s->self_buf,
            (const unsigned char *) d_user->username, strlen(d_user->username)
                    + 1)) {
        return RET_NO_MEMORY;
    }
    if (d_user->password == NULL || strcasecmp(d_user->password, "") == 0) {
        if (0 != byte_array_append_len(s->self_buf, "\x00", 1)) {
            return RET_NO_MEMORY;
        }
    } else {
        unsigned char scramble_password[20];
        if (0 != byte_array_append_len(s->self_buf,
                (const unsigned char *) "\x14", 1)) {
            return RET_NO_MEMORY;
        }

        scramble(scramble_password, server->handshake.scramble,
                d_user->password);

        if (0 != byte_array_append_len(s->self_buf,
                (const unsigned char *) scramble_password, 20)) {
            return RET_NO_MEMORY;
        }
    }
    if (client->current_db[0] == '\0') {
        if (d_user->default_db[0] == '\0') {
            log_error(logger,"client->current_db and db_user->default_db are both NULL");
            return RET_ERROR;
        }

        snprintf(client->current_db,sizeof(client->current_db),"%s",d_user->default_db);

        if (0 != byte_array_append_len(s->self_buf,
                (const unsigned char *) d_user->default_db, strlen(
                        d_user->default_db) + 1)) {
            return RET_NO_MEMORY;
        }
    } else {
        if (0 != byte_array_append_len(s->self_buf,
                (const unsigned char *) client->current_db, strlen(
                        client->current_db) + 1)) {
            return RET_NO_MEMORY;
        }
    }
    s->packet_id = 1;
    if (RET_SUCCESS != (ret = network_queue_send_append(server->send_buf,
            s->self_buf->data, s->self_buf->size, s->packet_id, 0))) {
        return ret;
    }
    if (RET_WAIT_FOR_EVENT == (ret = real_write(s))) {
        s->is_auth_send_partly = 1;
    }
    if (ret == RET_SUCCESS)
        byte_array_clear(s->self_buf);
    return ret;
}

inline int handshake_send(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "send handshake failed, network_socket s==NULL");
        return RET_ERROR;
    }
    int ret;
    if (1 == s->is_handshake_send_partly) {
        ret = real_write(s);
        s->is_handshake_send_partly = ret == RET_WAIT_FOR_EVENT ? 1 : 0;
        return ret;
    }
    const unsigned char packet_handshake[] = "\x0a" /* protocol version */
        "5.0.51b\x00" /* server version */
        "\x01\x00\x00\x00" /* thread id */
        "\x2f\x55\x3e\x74"
        "\x50\x72\x6d\x4b" /* scramble_buf */
        "\x00" /* filter */
        "\x0c\xa2" /* server capabilities */
        "\x1c" /* server language encoding :cp 1257 change to gbk*/
        "\x02\x00" /* server status */
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x56\x4c\x57"
        "\x54\x7c\x34\x2f"
        "\x2e\x37\x6b\x37"
        "\x6e\x00";
    if (RET_SUCCESS != (ret = network_queue_send_append(s->send_buf,
            packet_handshake, (sizeof(packet_handshake) - 1), 0, 0))) {
        return ret;
    }
    if (RET_WAIT_FOR_EVENT == (ret = real_write(s))) {
        s->is_handshake_send_partly = 1;
    }
    return ret;
}

inline int auth_result_send(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    int ret;
    if (1 == s->is_auth_result_send_partly) {
        ret = real_write(s);
        s->is_auth_result_send_partly = RET_WAIT_FOR_EVENT == ret ? 1 : 0;
        return ret;
    }
    s->packet_id = 2;
    const unsigned char packet_ok[] = "\x00\x00\x00\x02\x00\x00\x00";
    if (RET_SUCCESS != (ret = network_queue_send_append(s->send_buf, packet_ok,
            (sizeof(packet_ok) - 1), s->packet_id, 0))) {
        return ret;
    }
    if (RET_WAIT_FOR_EVENT == (ret = real_write(s))) {
        s->is_auth_result_send_partly = 1;
    }
    return ret;
}
extern int query_prepare_result_read(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }

    s->has_prepare_sql = 1;

    packet_result *result = &(s->result);
    byte_array *send_buf;
    if (NULL == s->client || NULL == (send_buf = s->client->send_buf)) {
        return RET_ERROR;
    }

    network_socket* client = s->client;

    int ret;
    if (STATE_READ_RESULT_BEGIN == result->state) {
        switch (ret = read_packet(s, send_buf)) {
        case RET_SUCCESS: {
            unsigned char *packet;
            packet = send_buf->data + s->header_offset;
            guint off = 0;
            off += PACKET_HEADER_LEN;
            guint64 type;
            if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
                log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
                return RET_ERROR;
            }

            if(type == 0) {

                if(client->is_sending_cache_cmds == 0) {
                    int statement_id = 0;

                    int id_off = 5;

                    if (RET_SUCCESS != protocol_get_statement_id(s, packet, &id_off, 4, &statement_id)) {
                        log_error(logger, "db fd=%d protocol_get_statement_id failed off=%d, len=4", s->fd, id_off);
                        return RET_ERROR;
                    }

                    client->statement_id++;
					if(client->statement_id == 2000000000) {
						client->statement_id = 0;
					}

                    client->query.statement_id = client->statement_id;

                    id_off = 5;
                    packet[id_off] = (unsigned char)((client->statement_id >> 0) & 0xFF);
                    packet[id_off+1] = (unsigned char)((client->statement_id >> 8) & 0xFF);
                    packet[id_off+2] = (unsigned char)((client->statement_id >> 16) & 0xFF);
                    packet[id_off+3] = (unsigned char)((client->statement_id >> 24) & 0xFF);

                    char* port_statementid = (char*)malloc(sizeof(char)*50);
                    if(port_statementid == NULL) {
                        log_warning(logger,"can't allocate memory for port and statement id");
                        return RET_ERROR;
                    }

                    snprintf(port_statementid,50,"%d:%d@%d",client->statement_id,s->port,statement_id);

					g_ptr_array_add(client->prepare_statement_ids,port_statementid);

                    //将prepare命令缓存起来
                    packet_query* cache_query = (packet_query*) calloc(1,sizeof(packet_query));
                    if (0 != packet_query_copy(&(client->query), cache_query)) {
                        log_error(logger,"copy prepare query failed");
                        return RET_ERROR;
                    }
                    g_ptr_array_add(client->cache_cmds, cache_query);

                    s->cache_cmd_index++;
                    //还需要将statement id 与主从对应起来
                    if(client->query.qtype == 0) {
                        g_array_append_val(client->prepare_write_array,client->statement_id);
                    } else {
                        g_array_append_val(client->prepare_read_array,client->statement_id);
                    }

					if(client->query.is_last_insert_id == 1) {
						client->query.is_last_insert_id = 0;
                        g_array_append_val(client->last_insert_id_array,client->statement_id);
					}


                } else if(client->is_sending_cache_cmds == 1){
                    packet_query* query = NULL;

                    query = (packet_query*) g_ptr_array_index(client->cache_cmds,s->cache_cmd_index - 1);

                    if(query == NULL) {
                        log_warning(logger,"can't find cached query");
                        return RET_ERROR;
                    }


                    int statement_id = 0;

                    int id_off = 5;

                    if (RET_SUCCESS != protocol_get_statement_id(s, packet, &id_off, 4, &statement_id)) {
                        log_error(logger, "db fd=%d protocol_get_statement_id failed off=%d, len=4", s->fd, id_off);
                        return RET_ERROR;
                    }
                    char* port_statementid = (char*)malloc(sizeof(char)*50);

                    if(port_statementid == NULL) {
                        log_warning(logger,"can't allocate memory for port and statement id");
                        return RET_ERROR;
                    }

                    snprintf(port_statementid,50,"%d:%d@%d",query->statement_id,s->port,statement_id);

					g_ptr_array_add(client->prepare_statement_ids,port_statementid);

                }
            }


            if (type == 255) {
                goto prepare_success;
            }
            off += 4;
            if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
                log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
                return RET_ERROR;
            }
            result->ret_column_cnt = type;

            off++;
            if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
                log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
                return RET_ERROR;
            }
            result->param_cnt = type;
            result->state = STATE_READ_PREPARE_RESULT_HEADER;

            if (0 >= result->param_cnt) {
                result->state = STATE_READ_PREPARE_RESULT_PARAMS_EOF;
                goto prepare_params_eof;
            }
            break;
        }
        case RET_WAIT_FOR_EVENT:
            return RET_WAIT_FOR_EVENT;
        case RET_ERROR:
            return RET_ERROR;
        default:
            return ret;
        }
    }
    if (STATE_READ_PREPARE_RESULT_HEADER == result->state) {
        int i;
        int cnt = result->param_cnt;
        for (i = 0; i < cnt; i++) {
            if (RET_SUCCESS != (ret = read_packet(s, send_buf))) {
                return ret;
            }
            result->param_cnt--;
        }
        result->state = STATE_READ_PREPARE_RESULT_PARAMS;
    }
    if (STATE_READ_PREPARE_RESULT_PARAMS == result->state) {
        switch (ret = read_packet(s, send_buf)) {
        case RET_SUCCESS:
            result->state = STATE_READ_PREPARE_RESULT_PARAMS_EOF;
            break;
        default:
            return ret;
        }
    }
    prepare_params_eof:
    if (STATE_READ_PREPARE_RESULT_PARAMS_EOF == result->state) {
        if (0 >= result->ret_column_cnt) {
            s->prepare_cnt++;
            goto prepare_success;
        }
        while (RET_SUCCESS == (ret = read_packet(s, send_buf))) {
            unsigned char *packet;
            packet = send_buf->data + s->header_offset;
            guint off = 0;
            off += PACKET_HEADER_LEN;
            int len;
            protocol_decode_len(packet, off, len);
            if (len < 0) {
                s->prepare_cnt++;
                goto prepare_success;
            }
        }
        return ret;
    }
    prepare_success: bzero(&(s->result), sizeof(s->result));
    return RET_SUCCESS;
}

unsigned long long length_code_binary(unsigned char *bytestream,guint *off) {
	if(bytestream == NULL || off == NULL) {
		log_error(logger,"bytestream or off is NULL");
		return -1;
	}
	unsigned long long ret = 0;
	if( bytestream[*off] < 251){ 
		ret = bytestream[*off]; 
		*off += 1;
	} else if(bytestream[*off] == 251){ 
		ret = 0; 
		*off += 1;
	} else if(bytestream[*off] == 252){ 
		ret = (bytestream[*off + 1] << 0 ) | (bytestream[*off + 2] << 8); 
		*off += 3;
	} else if(bytestream[*off] == 253){ 
		ret = (bytestream[*off + 1] << 0 ) | (bytestream[*off + 2] << 8) 
			| (bytestream[*off + 3] << 16); 
		*off += 4;
	} else if(bytestream[*off] == 254){ 
		ret = (*((unsigned long long *) (bytestream + *off + 1)));
        /*
		 *ret = (bytestream[*off + 1] << 0 ) | (bytestream[*off + 2] << 8) 
		 *    | (bytestream[*off + 3] << 16) | (bytestream[*off + 4] << 24) 
		 *    | (bytestream[*off + 5] << 32) | (bytestream[*off + 6] << 40) 
		 *    | (bytestream[*off + 7] << 48) | (bytestream[*off + 8] << 56); 
         */
		*off += 9;
	}
	return ret;
}

extern int query_result_read(network_socket *s) {

	if (NULL == s) {
		log_error(logger, "s==NULL");
		return RET_ERROR;
	}


	packet_result *result = &(s->result);
	network_socket *client = s->client;

    byte_array *send_buf;
    //send_buf 设置为client的buf，减少拷贝
    if (NULL == s->client || NULL == (send_buf = s->client->send_buf)) {
        log_error(logger, "s->client or client->send_buf is null, fd=%d", s->fd);
        return RET_ERROR;
    }

    int ret;
    unsigned int more_result = 0;
    if (client->is_sending_cache_cmds == 1) {
		if(client->cache_cmd == '\x16'){
			return query_prepare_result_read(s);
		} else {
			goto not_prepare;
		}
	}

    if (client->query.command == '\x16') {
        return query_prepare_result_read(s);
    }

	not_prepare:

    if (client->query.command == '\x04'|| client->query.command == '\x09' ||
            client->query.command == '\x0d' || client->query.command == '\x1b') {
        result->state = STATE_READ_RESULT_FIELDS_EOF;
    }
    switch (result->state) {
    case STATE_READ_RESULT_BEGIN: {
    	result->init_size = send_buf->size;
		if(client != NULL)
			client->result.result_set_size = 0;
    	switch (ret = read_packet(s, send_buf)) {
    	case RET_SUCCESS: {
    		unsigned char *packet;
    		packet = send_buf->data + s->header_offset;
    		guint off = 0;
    		off += PACKET_HEADER_LEN;
    		guint64 type;
    		if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
    			log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
    			return RET_ERROR;
    		}
    		if (type == 0) {
				if(SQL_USE_NUM == client->query.type || SQL_USE_IN_QUERY_NUM == client->query.type){
					client->has_use_sql = 1;

					packet_query *cache_query = (packet_query*) calloc(1,sizeof(packet_query));
					packet_query *query = &(client->query);
					if(cache_query == NULL){
						log_error(logger,"calloc memory failed, need %d bytes, no enough memory", sizeof(packet_query));
						return RET_ERROR;
					}
					if (0 != packet_query_copy(query, cache_query)) {
						log_error(logger,"copy use query failed");
						return RET_ERROR;
					}
					//g_ptr_array_add(s->cache_cmds, cache_query);
					//add by ybx
					if (g_ptr_array_no_repeat_add(client->cache_cmds,cache_query) == 0){
						log_error(logger,"cache_query is null");
						return RET_ERROR;
					}
				}
    			unsigned long long  affected_rows = 0;
    			unsigned long long  last_insert_id = 0;

    			affected_rows = length_code_binary(packet,&off);
    			last_insert_id = length_code_binary(packet,&off);

    			client->result.qstatus.affected_rows = affected_rows;	//server的result在本函数最后被清空，所以把信息存到client里
    			if(last_insert_id != 0) {
    				client->last_insert_id = last_insert_id;
    			}
    			more_result =(unsigned short)((unsigned short)((unsigned char)(packet[off]))+((unsigned short)((unsigned char)(packet[off+1]))<<8));
    			goto success;
    		} else if (type == 255) {
    			if(SQL_USE_NUM == client->query.type || SQL_USE_IN_QUERY_NUM == client->query.type){
					client->current_db[0] = '\0';
				}
				//short unsigned int err = 0;
				guint64 err = 0;
    			if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 2, &err)){
    				log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=2", s->fd, off);
    			}
    			off += 6;
				*(packet + s->packet_len + PACKET_HEADER_LEN) = '\0';	//mysql协议中说已经加了\0，但实际上没加，这里加上
				char log_cmd[MAX_LOG_SQL_LEN];
				truncate_str_two_ends(log_cmd, client->query.args, client->query.args_len-1);
    			log_error(logger,"SQL=%s, errno=%d, error: %s", log_cmd, err, packet+off);
    			if ( err == 1037 || err == 1038 ){
    				s->is_during_err = 1;
    			}
    			goto success;
    		}
    		else if (type == 251) {
    			;
    		}
    		off--;
    		guint64 column_cnt = length_code_binary(packet,&off);
    		result->column_cnt = column_cnt;
    		result->state = STATE_READ_RESULT_HEADER;
    		break;
    	}
    	case RET_WAIT_FOR_EVENT:
    		return RET_WAIT_FOR_EVENT;
    	case RET_ERROR:
    		return RET_ERROR;
    	case RET_SHUTDOWN:
    		return RET_SHUTDOWN;
    	}
    }
    case STATE_READ_RESULT_HEADER: {
    	int i;
    	int cnt = result->column_cnt;
    	for (i = 0; i < cnt; i++) {
    		if (RET_SUCCESS != (ret = read_packet(s, send_buf))) {
    			return ret;
    		}
    		result->column_cnt--;
    	}
    	result->state = STATE_READ_RESULT_FIELDS;
    }
    case STATE_READ_RESULT_FIELDS: {
    	switch (read_packet(s, send_buf)) {
    	case RET_SUCCESS:
    		result->state = STATE_READ_RESULT_FIELDS_EOF;
    		break;
    	case RET_WAIT_FOR_EVENT:
    		return RET_WAIT_FOR_EVENT;
    	}
    }
    case STATE_READ_RESULT_FIELDS_EOF: {
    	while (RET_SUCCESS == (ret=read_packet(s, send_buf))) {
    		unsigned char *packet;
    		packet = send_buf->data + s->header_offset;
    		guint off = 0;
    		off += PACKET_HEADER_LEN;
    		int len;
    		protocol_decode_len(packet, off, len);
    		if (len < 0){
    			off += 2;
    			more_result =(unsigned short)((unsigned short)((unsigned char)(packet[off]))+((unsigned short)((unsigned char)(packet[off+1]))<<8));
    			goto success;
    		}
    		if(client->query.command == '\x09' || client->query.command == '\x1b'){
    			goto success;
    		}
    		if (len == 0 && client->query.command == '\x04'){
    			goto success;
    		}
    	}
    	return ret;
    }
	default:{
		break;
	}
    }
    success: bzero(&(s->result), sizeof(s->result));
    if (more_result & SERVER_MORE_RESULTS_EXISTS){
        return RET_WAIT_FOR_EVENT;
    }
    else
        return RET_SUCCESS;
}

inline int auth_result_read(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    int ret;
    ret = read_packet(s, s->self_buf);
    if (ret != RET_SUCCESS)
        return ret;
    guint off = 0;
    off += PACKET_HEADER_LEN;
    unsigned char *packet;
    packet = s->self_buf->data + s->header_offset;
    guint64 type;
    if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
        log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
        return RET_ERROR;
    }
    if (type != '\x00'){
        guint64 auth_errno;
        if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 2,
                &auth_errno)) {
            log_error(logger,"db fd=%d protocol_get_int_len faild off=%d,len=2 handshake errno",s->fd,off);
            return RET_AUTH_FAILED;
        }
        char error_msg[s->packet_len];
        snprintf(error_msg, s->packet_len - 2,"%s", packet + 7);
        error_msg[s->packet_len - 1] = '\x00';
        log_warning(logger, "db socket fd=%d server ip=%s,read auth_result error: mysql errno{%d} message {%s}",s->fd,s->db->addr.addr_name,(int)auth_errno,error_msg);

        return RET_AUTH_FAILED;
    }
    return ret;
}

extern int handshake_read(network_socket *s) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return RET_ERROR;
    }
    int ret;
    ret = read_packet(s, s->self_buf);
    if (RET_SUCCESS != ret)
        return ret;
    unsigned char *packet;
    packet = s->self_buf->data + s->header_offset;

    packet_handshake *handshake = &(s->handshake);

    guint off = 0;
    off += PACKET_HEADER_LEN;

    guint64 type;
    if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1, &type)) {
        log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
        return RET_ERROR;
    }
    if (255 == type) {
        guint64 handshake_errno;
        if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 2,
                &handshake_errno)) {
            log_error(logger,"db fd=%d protocol_get_int_len failed off=%d,len=2 handshake errno",s->fd,off);
            return RET_ERROR;
        }
        char error_msg[s->packet_len];
        snprintf(error_msg, s->packet_len - 2,"%s", packet + 7);
        error_msg[s->packet_len - 1] = '\x00';
        log_warning(logger, "db socket fd=%d server ip=%s,read handshake error: mysql errno{%d} message {%s}",s->fd,s->db->addr.addr_name,(int)handshake_errno,error_msg);

        //当前数据库服务器已经达到最大连接数，检查数据库连接，释放超时时间大于server_timeout_short的连接
        if(s->db == NULL || s->srv == NULL){
            log_warning(logger,"s->db == NULL || s->srv == NULL, fd=%d",s->fd);
            return RET_HANDSHAKE_ERROR;
        }
        struct timeval cur_timeval;
        gettimeofday(&(cur_timeval), 0);
        time_t cur_time = cur_timeval.tv_sec;
        time_t active_interval = 0;
        int k;
        for (k = 0; k <= s->srv->poll->max_fd; k++) {
            network_socket *cur_s;
            if (NULL == (cur_s = s->srv->poll->fd_mapping[k])) {
                continue;
            }
            if(cur_s->db == NULL){
                log_warning(logger,"cur_s->db == NULL, fd=%d",cur_s->fd);
                continue;
            }
            active_interval = cur_time - cur_s->last_active_time;
            if (cur_s->is_client_socket == 1
                    && s->srv->config->server_timeout_short
                            < active_interval
                    && cur_s->db->addr.addr_ip.sin_addr.s_addr
                            == s->db->addr.addr_ip.sin_addr.s_addr
                    && cur_s->db->addr.addr_ip.sin_port
                            == s->db->addr.addr_ip.sin_port) {
                log_load(logger, "database %s has reach the max connection and client socket fd=%d timeout=%d > server_timeout_short=%d", cur_s->db->addr.addr_name,s->fd,
                        active_interval, s->srv->config->server_timeout_short);
                client_free(cur_s, 1);
                cur_s = NULL;
                continue;
            }
        }
        return RET_HANDSHAKE_ERROR;
    }

    if (0 != protocol_get_string(packet, s->packet_len + 4, &off, NULL, 0)) {
        log_error(logger, "db socket fd=%d read handshake from db server failed, server_version is null",s->fd);
        return RET_ERROR;
    }

    if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 4, &type)) {
        log_error(logger, "db fd=%d protocol_get_int_len failed off=%d, len=4", s->fd, off);
        return RET_ERROR;
    }
    handshake->thread_id = type;
    memcpy(handshake->scramble, packet + off, 8);
    off += 27; // 8 bytes scramble 1 byte '00' 18 bytes always
    memcpy(handshake->scramble + 8, packet + off, 12);
    off += 13; // 12 bytes scramble 1 byte '00'
    *(handshake->scramble + 20) = '\0';
    return ret;
}

inline int auth_read(network_socket *s, network_server *srv) {
    if (NULL == s || srv == NULL) {
        log_error(logger, "s==NULL || srv==NULL");
        return RET_ERROR;
    }
    int ret;
    ret = read_packet(s, s->self_buf);
    if (RET_SUCCESS != ret) {
        return ret;
    }

    //在这里调用二次开发钩子
    int hookIndex;
    for (hookIndex = 0; hookIndex < srv->config->h_array->so_nums; hookIndex++) {

        int ret = call_hook_func(hookIndex,1,&s,-1);
        if (ret == 0) {
            continue;
        } else if (ret == 1) {
            return RET_SUCCESS;
        }
    }

    unsigned char *packet;
    packet = s->self_buf->data + s->header_offset;

    guint off = 0;
    off += PACKET_HEADER_LEN;
    off += 32;
    if (s->packet_len + PACKET_HEADER_LEN < off + 1) {
        log_error(logger, "s->packet_len=%d + PACKET_HEADER_LEN=%d < off=%d + 1", s->packet_len, PACKET_HEADER_LEN, off);
        return RET_ERROR;
    }

    char p_username[MAX_USERNAME_LEN];
    if (0 != protocol_get_string(packet, s->packet_len + 4, &off, p_username,
            MAX_USERNAME_LEN)) {
        log_warning(logger, "client->db_user.username is null, fd=%d", s->fd);
        return RET_AUTH_FAILED;
    }

	unsigned int client_flag = 0;
	client_flag = packet[PACKET_HEADER_LEN] | (packet[PACKET_HEADER_LEN+1] << 8)
		| (packet[PACKET_HEADER_LEN+2] << 16) | (packet[PACKET_HEADER_LEN+3] << 24);
	s->client_found_rows = (client_flag & 2) > 0 ? 1 : 0;
	s->client_ignore_space = (client_flag & 256) > 0 ? 1 : 0;
	//log_debug(logger, "client_flag=%d, client_found_rows=%d, client_ignore_space=%d",
	//			client_flag, s->client_found_rows, s->client_ignore_space);

    product_user *user;

    if (NULL == (user = g_hash_table_lookup(srv->config->users, p_username))) {
        log_warning(logger, "g_hash_table_lookup doesn't have user=%s", p_username);
        s->p_user = NULL;
        return RET_AUTH_FAILED;
    }
    s->p_user = user;

    if (s->is_check_ip == 0) {
        int i_len = user->auth_ips->len;
        int i;
        for (i = 0; i < i_len; i++) {
            auth_ip *ip = g_ptr_array_index(user->auth_ips,i);
            if (ip->addr.s_addr == s->addr.sin_addr.s_addr) {
                break;
            }
        }
        if (i == i_len) {
            char *client_ip = NULL;
            client_ip = (char*)inet_ntoa(s->addr.sin_addr);
            if(client_ip != NULL){
                log_warning(logger,"not auth ip %s ", client_ip);
            }
            return RET_AUTH_FAILED;
        }
    }

    //这里要处理旧的用户名
    if (user->is_old != s->srv->config->user_update_flag) {
        log_error(logger,"the username:%s is old and should not be used",user->username);
        return RET_AUTH_FAILED;
    }

    if(user->d_user == NULL || user->d_user->is_old != s->srv->config->user_update_flag){
        log_error(logger,"the db_user for user %s is NULL or is old",user->username);
        return RET_AUTH_FAILED;
    }

    if (s->packet_len + PACKET_HEADER_LEN < off + 1) {
        log_error(logger, "s->packet_len=%d + PACKET_HEADER_LEN=%d <= off=%d + 1", s->packet_len, PACKET_HEADER_LEN, off);
        return RET_ERROR;
    }
    unsigned char len;
    len = packet[off];
    off++;

    if (len == '\x00' && user->scramble_len == 1 && *(user->scramble_password)
            == '\x00') {
    } else if (len == '\x14' && user->scramble_len == 21) {
        if ((s->packet_len + PACKET_HEADER_LEN) < 20 + off) {
            log_error(logger, "s->packet_len=%d + PACKET_HEADER_LEN=%d < 20 + off=%d", s->packet_len, PACKET_HEADER_LEN, off);
            return RET_ERROR;
        }
        int i;
        for (i = 0; i < 20; i++) {
            if (*(packet + off + i) != *(user->scramble_password + i + 1)) {
                log_warning(logger, "client fd=%d auth failed with wrong scramble", s->fd);
                return RET_AUTH_FAILED;
            }
        }
        off += 20;
    } else {

        log_warning(logger, "client fd=%d auth failed user->scramble_len=%d client->scramble_len=%d", s->fd,
                user->scramble_len, len);
        return RET_AUTH_FAILED;
    }

    //这里要设置current_db
    int client_connect_with_db = (client_flag & 8) > 0 ? 1 : 0;
	if(client_connect_with_db == 0) {
		if(s->p_user->d_user != NULL && s->p_user->d_user->default_db[0] != '\0'){
            snprintf(s->current_db,sizeof(s->current_db),"%s",s->p_user->d_user->default_db);
			fill_use_packet(s,s->current_db,strlen(s->current_db) + 1);
        } else {
            s->current_db[0] = '\0';
        }
		log_debug(logger, "client_connect_with_db=0, default db is %s", s->current_db);
		return RET_SUCCESS;
 	} else if (s->packet_len + PACKET_HEADER_LEN < off + 1) {
        log_warning(logger, "there supposed to be dbname in auth packet, but actually not, fd=%d", s->fd);
        s->current_db[0] = '\0';
        return RET_AUTH_FAILED;
    } else {
        if (0 != protocol_get_string(packet, s->packet_len + 4, &off,
                s->current_db, MAX_DEFAULT_DB_NAME_LEN)) {
            log_warning(logger, "get dbname from auth packet failed, s->current_db is null, fd=%d", s->fd);
            return RET_AUTH_FAILED;
        }
		fill_use_packet(s,s->current_db,strlen(s->current_db) + 1);
		log_debug(logger, "client_connect_with_db=1, db is %s", s->current_db);
        return RET_SUCCESS;
    }
}
int remove_network_database(network_database *db, GPtrArray *dbs) {
    network_database *cur_db = NULL;
    int dbs_len = dbs->len;
    int i;
    for (i = 0; i < dbs_len; i++) {
        cur_db = g_ptr_array_index(dbs, i);
        if (my_strncasestr(db->addr.addr_name, cur_db->addr.addr_name,
                MAX_IP_LEN, MAX_IP_LEN, 1) == 1 && db->addr.port
                == cur_db->addr.port) {
            g_ptr_array_remove_index(dbs, i);
            return 0;
        }
    }
    return 1;
}
extern void server_free(network_socket *s, int p_client) {

    if (NULL == s) {
        log_error(logger, "s==NULL");
        return;
    }
    if (NULL == s->db) {
        log_warning(logger, "s->db == NULL, fd=%d", s->fd);
        return;
    }
    /* 修复cur_connected可以被减为负值的bug ——by lzj */
    if(s->db->cur_connected > 0){
        s->db->cur_connected--;
    }

    if(s->is_in_pool == 1){
        if (0 != conn_pool_delete(s)) {
            log_error(logger, "conn_pool_delete failed, fd=%d, address=%#0x", s->fd, s);
            return;
        }
    }

    if(s->ms == MS_MASTER){
        if (s->db->is_old != s->db->clus->w_update_flag && s->db->cur_connected
                <= 0) {
            remove_network_database(s->db, s->db->clus->master_dbs);
            network_database_free(s->db);
            s->db = NULL;
            if(s->client != NULL){
                s->client->db = NULL;
                s->client->is_using_db = 0;
            }
        }
    } else {
        if (s->db->is_old != s->db->clus->r_update_flag && s->db->cur_connected
                <= 0) {
            remove_network_database(s->db, s->db->clus->slave_dbs);
            network_database_free(s->db);
            s->db = NULL;
            if(s->client != NULL){
                s->client->db = NULL;
                s->client->is_using_db = 0;
            }
        }
    }


    if (p_client == 1) {
        s->is_clean = 0;
        if (NULL != s->client) {
            client_free(s->client, 0);
        }
    }
    if (s->fd >= 0 && s->fd < CONFIG_MPL_EPOLL_MAX_SIZE) {
        s->poll->fd_mapping[s->fd] = NULL;
    }
    poll_events_delete(s->poll, s);
    network_socket_put_back(s);
}

inline int is_db_socket_reuseable(network_socket *server) {
    if (NULL == server)
        return 0;
    if (NULL == server->srv) {
        log_error(logger, "db socket fd=%d, ms=%d , state=%d, server->srv is null",
                server->fd, server->ms, server->state);
        return 0;
    }
    if (server->is_clean == 1 && server->state == STATE_READ_AUTH_RESULT
            && server->is_query_send_partly == 0 && server->is_auth_send_partly
            == 0 && server->is_handshake_send_partly == 0
            && server->is_auth_result_send_partly == 0
            && server->served_client_times
                    < server->srv->config->conn_pool_socket_max_serve_client_times
            && server->has_call_sql == 0 && server->has_set_sql == 0 
            && server->has_changeuser_sql == 0 && server->has_prepare_sql == 0
            && server->prepare_cnt <= 0
			&& (server->client != NULL  && server->client->is_transaction == 0) && server->loading_data == 0 && server->is_during_err == 0) {

		server->cache_cmd_index = 0;
		//log_debug(logger, "reuse db socket");
        return 1;
    }
	//log_debug(logger, "destroy db socket,server->is_clean=%d,server->client->is_transaction=%d",server->is_clean,server->client->is_transaction);
    return 0;
}

void clear_queue(GQueue *q) {
    network_socket *server;
    int q_len;
    q_len = q->length;
    while (q_len != 0) {
        server = g_queue_pop_head(q);
        server_free(server, 0);
        q_len--;
    }
}
extern void client_free(network_socket *s, int p_server) {
    if (NULL == s) {
        log_error(logger, "s==NULL");
        return;
    }
    //将连接从会话表中删除
    g_hash_table_remove(s->srv->config->sessions,&(s->session_key));

    network_server *srv = s->srv;

    //这里减少业务端连接数
    if (s->is_authed == 1) {
        s->p_user->current_connections--;
        if (s->is_using_db == 1 && s->p_user->d_user != NULL) {
            s->p_user->d_user->current_connections--;
        }
    }

    if (s->p_user != NULL && s->p_user->d_user != NULL && s->p_user->d_user->current_connections
            <= 0 && s->p_user->d_user->is_old
            != s->srv->config->user_update_flag) {

        //这里还需要对连接池做处理
        cluster *clus = s->p_user->d_user->clus;

        GHashTable *db_user_mapping = g_hash_table_lookup(clus->db_conn_pools,
                s->p_user->d_user->username);

        GList *db_name_keys = g_hash_table_get_keys(db_user_mapping);
        GList *db_name_head = db_name_keys;
        while (NULL != db_name_head) {
            conn_pool_queue *queue = g_hash_table_lookup(db_user_mapping,
                    (char*) db_name_head->data);

            clear_queue(queue->w_queue);

            clear_queue(queue->r_queue);

            conn_pool_queue_free(queue);

            db_name_head = db_name_head->next;
        }

        g_hash_table_destroy(db_user_mapping);

        g_hash_table_remove(clus->db_conn_pools, s->p_user->d_user->username);

        g_hash_table_remove(s->srv->config->db_user,
                s->p_user->d_user->username);
        free(s->p_user->d_user);
        s->p_user->d_user = NULL;
    }

    if (s->p_user != NULL && s->p_user->is_old != s->srv->config->user_update_flag
            && s->p_user->current_connections <= 0) {
        g_hash_table_remove(s->srv->config->users, s->p_user->username);

        free(s->p_user);
        s->p_user = NULL;

    }


    if (p_server == 1) {
        network_socket *server = s->server;
        if (1 == is_db_socket_reuseable(server)) {
            if (0 != conn_pool_add(server)) {
                log_warning(logger, "add clean db socket to conn_pool failed, db fd=%d", server->fd);
                server_free(server, 0);
            }
        } else {
            if (NULL != server) {
                if (server->served_client_times
                        >= srv->config->conn_pool_socket_max_serve_client_times) {
                    log_load(logger, "network_socket fd=%d ms=%d served client %d times, going to free",
                            server->fd, server->ms,server->served_client_times);
                }
                server_free(server, 0);
            }
        }
    }
    if (s->fd >= 0 && s->fd < CONFIG_MPL_EPOLL_MAX_SIZE) {
        s->poll->fd_mapping[s->fd] = NULL;
    }
    poll_events_delete(s->poll, s);
    network_socket_put_back(s);
}
inline int is_valid_command(unsigned char command) {

    //基本上所有的命令号都兼顾到了
    if (command == '\x01' || command == '\x02' || command == '\x03' || command
            == '\x04' || command == '\x05' || command == '\x06' || command
            == '\x07' || command == '\x08' || command == '\x09' || command
            == '\x0a' || command == '\x0c' || command == '\x0d' || command
            == '\x0e' || command == '\x11' || command == '\x16' || command
            == '\x17' || command == '\x18' || command == '\x19' || command
            == '\x1a' || command == '\x1b' || command == '\x1c') {
        return 1;
    }
    return 0;
}
inline int is_the_end(unsigned char *p) {
    unsigned char byte = *p;
    if (byte == ' ' || byte == '\t' || byte == '\x0B' || byte == '\0' || byte
            == ';' || byte == '\r' || byte == '\n') {
        return 1;
    }
    return 0;
}
inline int is_same_database(packet_query *query, char *dbname) {
    if (query->command == '\x02') {
        int len = strlen(dbname);
        int args_len = query->args_len - 1;
        if (len <= 0 || args_len <= 0 || len != args_len)
            return 0;
        if (1 == my_strncasestr(query->args, (unsigned char*) dbname, args_len,
                len, 0)) {
            return 1;
        }
    }
    return 0;
}
inline int is_same_database_in_query(char *db_in_query, char *dbname) {
    int db_in_query_len = strlen(db_in_query);
    int db_len = strlen(dbname);
    if (db_in_query_len <= 0 || db_len <= 0 || db_in_query_len != db_len)
        return 0;
    if (1 == my_strncasestr((unsigned char*)db_in_query, (unsigned char*) dbname, db_in_query_len, db_len, 0)){
        return 1;
    }                          
    return 0;   
}     

extern int query_read(network_socket *s, network_server *srv) {

    int ret;

    GPtrArray *cmd_cache = NULL;
    packet_query *cache_query = NULL;

    if (NULL == s) {
        ret = RET_ERROR;
        log_error(logger, "s==NULL");
        goto return_step;
    }

    ret = read_packet(s, s->self_buf);

    if (RET_SUCCESS != ret) {
        goto return_step;
    }

    int hookIndex;
    for (hookIndex = 0; hookIndex < srv->config->h_array->so_nums; hookIndex++) {
        int ret = call_hook_func(hookIndex,2,&s,-1);
        if (ret == 0) {
            continue;
        } else if (ret == 1) {
            return RET_SUCCESS;
        }
    }

    guint off = 0;
    off += PACKET_HEADER_LEN;

    if (s->query.status == QUERY_USING) {
        log_error(logger, "s->fd=%d query status=%d using", s->fd, s->query.status);
        return RET_ERROR;
    }

    packet_query *query = &(s->query);

    unsigned char *packet;

    //packet指向当前query,包括header
    packet = s->self_buf->data + s->header_offset;

    //这里读取命令类型
    if (RET_SUCCESS != protocol_get_int_len(s, packet, &off, 1,
            &(query->command))) {
        log_error(logger, "client fd=%d protocol_get_int_len failed off=%d, len=1", s->fd, off);
        ret = RET_ERROR;
        goto return_step;
    }

    //判断是否为合法的命令
    if (is_valid_command(query->command) != 1) {
        char *message = "denied command -_-||";
        if (RET_SUCCESS != (ret = fill_string_packet(s, message,
                strlen(message)))) {
            goto return_step;
        }
        ret = RET_REAL_WRITE;
        goto return_step;
    }

    if ('\x01' == query->command || '\x08' == query->command || '\x0c'
            == query->command) {
        ret = RET_COMMAND_SHUTDOWN;
        goto return_step;
    }

    if (0 < (query->args_len = (s->packet_len - 1))) {
        //到这里的时候off已经等于5
        ret = protocol_get_byte_len(packet, &off, query);
        if (ret != 0) {
            log_error(logger, "protocol_get_byte_len ret=%d", ret);
            goto return_step;
        }
    }

    s->query.status = QUERY_USING;

    int qtype;

    int is_trans_end = 0;
    int is_last_query_in_trans = s->is_transaction;

    qtype = get_query_type(query);

    //不做特别处理的命令04、05、06、07、09、0a、0d、0e
    query->type = qtype;
    if (SQL_CALL_NUM == qtype) {
        s->has_call_sql = 1;
    } else if (SQL_SET_NUM == qtype) {
        s->has_set_sql = 1;
    } else if (is_not_repeatable(qtype) && qtype != SQL_USE_NUM && qtype != SQL_USE_IN_QUERY_NUM){
       s->has_set_sql = 1;
    } else if (SQL_USE_NUM == qtype) {	//init db
        product_user *user;

        if (NULL == (user = g_hash_table_lookup(srv->config->users,
                s->p_user->username))) {
            log_error(logger, "query read doesn't have user=%s", s->p_user->username);
            ret = RET_ERROR;
            goto return_step;
        }

        if(query->args_len == 0){	//dbname==""，不同于" "
        	char *message = "No database selected";
        	if(RET_SUCCESS != (ret = fill_string_packet(s, message, strlen(message)))) {
				log_error(logger,"fill string packet failed, message=%s", message);
                goto return_step;
            }
			log_error(logger, "No database specified when init db");
        	ret = RET_REAL_WRITE;
        	goto return_step;
        }

        if (1 == is_same_database(query, s->current_db)) {
            if (RET_SUCCESS != (ret = fill_ok_packet(s))) {
                goto return_step;
            }
            ret = RET_REAL_WRITE;
            goto return_step;
        }

        if(query->args_len > MAX_DEFAULT_DB_NAME_LEN){
			char log_cmd[MAX_LOG_SQL_LEN];
			truncate_str_two_ends(log_cmd, query->args, query->args_len-1);
        	char *message = "The database name is too long. Max length is 64";
			if(RET_SUCCESS != (ret = fill_string_packet(s, message, strlen(message)))) {
				log_error(logger, "fill string packet failed, message=%s", message);
				goto return_step;
			}
            log_warning(logger,"use db error, cmd=%s, %s", log_cmd, message);
			ret = RET_REAL_WRITE;
			goto return_step;
        }
        snprintf(s->current_db, query->args_len,"%s", query->args);
    } else if(SQL_USE_IN_QUERY_NUM == qtype) {	//use db

        product_user *user;

        if (NULL == (user = g_hash_table_lookup(srv->config->users,
                s->p_user->username))) {
            log_error(logger, "query read doesn't have user=%s", s->p_user->username);
            ret = RET_ERROR;
            goto return_step;
        }

        char db_in_query[MAX_DEFAULT_DB_NAME_LEN];
        unsigned char *p = query->args;
        unsigned char *e_pos = query->args + query->args_len -2;
        unsigned char *d_pos = NULL;
        int cnt = start_trim_from_left(p, query->args_len);
        int len1 = query->args_len - cnt - 3;
        p = p + cnt + 3;
        cnt = start_trim_from_left(p, len1);
        p = p + cnt;
        d_pos = p;
        len1 = 1;

		if(*p == '`') {
			p += 1;
			d_pos = p;
		}

        while (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' && *p
                != '\x0B' && *p != ';' && *p != '`' && p <= e_pos) {
            p += 1;
            len1++;
        }

        if(len1 > MAX_DEFAULT_DB_NAME_LEN){
			char log_cmd[MAX_LOG_SQL_LEN];
			truncate_str_two_ends(log_cmd, query->args, query->args_len-1);
        	char *message = "The database name is too long. Max length is 64";
			if(RET_SUCCESS != (ret = fill_string_packet(s, message, strlen(message)))) {
				log_error(logger, "fill string packet failed, message=%s", message);
				goto return_step;
			}
            log_warning(logger,"use db error, cmd=%s, %s", log_cmd, message);
			ret = RET_REAL_WRITE;
			goto return_step;
            //return RET_ERROR;
        }
        snprintf(db_in_query,len1,"%s",d_pos);

        if(db_in_query[0] == '\0'){
        	char *message = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1";
			if(RET_SUCCESS != (ret = fill_string_packet(s, message, strlen(message)))) {
				log_error(logger, "fill string packet failed, message=%s", message);
				goto return_step;
			}
			log_error(logger, "No database specified when using db");
			ret = RET_REAL_WRITE;
			goto return_step;
        }

		if(1 == is_same_database_in_query(db_in_query,s->current_db)){

            if (RET_SUCCESS != (ret = fill_ok_packet(s))) {
                goto return_step;
            }
            ret = RET_REAL_WRITE;
            goto return_step;
        }

        snprintf(s->current_db, sizeof(s->current_db),"%s", db_in_query);
    } else if (SQL_CHANGEUSER_NUM == qtype) {

        s->has_changeuser_sql = 1;
    } else if (SQL_AUTOCOMMIT_1_NUM == qtype) {
        if (s->is_transaction == 2){
            is_trans_end = 1;
            s->is_transaction = 0;
        }
    } else if (SQL_AUTOCOMMIT_0_NUM == qtype) {
        s->is_transaction = 2;
    } else if (SQL_START_TRANSACTION_NUM == qtype) {
        if (s->is_transaction == 0)
            s->is_transaction = 1;
    } else if (SQL_COMMIT_NUM == qtype) {
        if (s->is_transaction == 1){
            is_trans_end = 1;
            s->is_transaction = 0;
        }
    } else if (SQL_ROLLBACK_NUM == qtype) {
        if (s->is_transaction == 1){
            is_trans_end = 1;
            s->is_transaction = 0;
        }
    } else if (SQL_BEGIN_NUM == qtype) {
        if (s->is_transaction == 0)
            s->is_transaction = 1;
    } else if (SQL_DESIGNATED_DB_NUM == qtype) {
        s->before_ms = s->ms;
        if (query->designated_type == 1) {
            s->ms = MS_MASTER;
            s->is_last_query_write = 1;
            gettimeofday(&(s->write_time), 0);
        }
        s->is_designated = 1;
        ret = RET_SUCCESS;
        goto return_step;
    } else if (SQL_PROXY_STATUS_NUM == qtype) {

        if(srv->config->proxy_status_interval <= 0){
            char *message = "denied command -_-||";
            if (RET_SUCCESS != (ret = fill_string_packet(s, message,
                    strlen(message)))) {
                goto return_step;
            }
            ret = RET_REAL_WRITE;
            goto return_step;
        }
        ret = RET_SUCCESS;
        s->before_ms = s->ms;
        goto return_step;
    } else if (SQL_LAST_INSERT_ID_NUM == qtype && s->query.command == '\x03') {

        ret = RET_SUCCESS;
        s->before_ms = s->ms;
        goto return_step;
    }

    int before_ms = s->ms;
    s->before_ms = s->ms;

    //在这里需要对长连接进行处理,还有事务。
    int qflag = is_read_query(qtype);
    
    if(s->is_designated == 1 ){
        goto ms_end_step;
    }


    //以下为读写分离策略
	if (s->is_transaction > 0) {
		//如果当前在事务中，则强制走主库
		s->ms = MS_MASTER;
        s->is_last_query_write = 1;
        gettimeofday(&(s->write_time), 0);
        goto ms_end_step;
    } else {
        if (is_trans_end && is_last_query_in_trans >= 1) {
            is_trans_end = 0;
            s->is_transaction = 0;
            s->is_last_query_write = 1;
            gettimeofday(&(s->write_time), 0);
            s->ms = MS_MASTER;
            goto ms_end_step;
        }

        if (qflag == 0) {
            //写操作，走主库
            s->ms = MS_MASTER;
            s->is_last_query_write = 1;
            gettimeofday(&(s->write_time), 0);
            goto ms_end_step;
        }

        //读操作，但是离上一个写操作的时间间隔尚未超过设定的值，走主库
        if (qflag == 1 && s->is_last_query_write == 1 && before_ms == MS_MASTER
                && (srv->cur_time.tv_sec * 1000000 + srv->cur_time.tv_usec - s->write_time.tv_sec * 1000000 - s->write_time.tv_usec)
                        < srv->config->write_time_interval) {
            s->ms = MS_MASTER;
			s->is_last_query_write = 1;
			/*gettimeofday(&(s->write_time), 0);*/
            goto ms_end_step;
        }

        if (1 == qflag) {
            s->ms = MS_SLAVE;
        } else if (2 == qflag) {

            //如果命令为execute或者long data等与prepare相关的命令，则首先在这里需要根据命令中的statement id来判断是走主库还是走从库
            if(query->command == '\x17' || query->command == '\x18' || query->command == '\x19' || query->command == '\x1a' || query->command == '\x1c') {
                off = 5;
                int statement_id = 0;
                if (RET_SUCCESS != protocol_get_statement_id(s, packet, &off, 4,
                        &statement_id)) {
                    log_error(logger, "client fd=%d protocol_get_statement_id failed off=%d, len=4", s->fd, off);
                    ret = RET_ERROR;
                    goto return_step;
                }

                int i = 0;
                int temp_id = 0;

				if(query->command == '\x17') {
					for(i = 0; i < s->last_insert_id_array->len; i++){
						temp_id = g_array_index(s->last_insert_id_array,int,i);
						if(temp_id == statement_id){
							ret = RET_SUCCESS;
							s->before_ms = s->ms;
							s->is_execute_last_insert_id = 1;
							goto return_step;
						}
					}
				}

				for(i = 0; i < s->prepare_read_array->len; i++){
                    temp_id = g_array_index(s->prepare_read_array,int,i);
                    if(temp_id == statement_id){

                        if (s->is_last_query_write == 1 && before_ms == MS_MASTER
                                && (srv->cur_time.tv_sec * 1000000 + srv->cur_time.tv_usec - s->write_time.tv_sec * 1000000 - s->write_time.tv_usec)
                                < srv->config->write_time_interval) {
                            s->ms = MS_MASTER;
							s->is_last_query_write = 1;
							/*gettimeofday(&(s->write_time), 0);*/
                        } else {
                            s->ms = MS_SLAVE;
                        }
                        goto ms_end_step;
                    }
                }

                if(i == s->prepare_read_array->len) {
                    for(i = 0; i < s->prepare_write_array->len; i++) {
                        temp_id = g_array_index(s->prepare_write_array,int,i);

                        if(temp_id == statement_id){
                            s->ms = MS_MASTER;
							s->is_last_query_write = 1;
							gettimeofday(&(s->write_time), 0);
                            goto ms_end_step;
                        }
                    }

                    if(i == s->prepare_write_array->len) {
                        log_warning(logger,"can't find the statment id in both read and write array");
                        s->ms = MS_MASTER;
						s->is_last_query_write = 1;
						gettimeofday(&(s->write_time), 0);
                        goto ms_end_step;
                    }
                }
            }


            s->ms = s->ms == MS_UNKNOWN ? MS_SLAVE : s->ms;
        } else {
            s->ms = MS_MASTER;
			s->is_last_query_write = 1;
			gettimeofday(&(s->write_time), 0);
        }
    }


    ms_end_step:


    query->qtype = qflag;
	cmd_cache = s->cache_cmds;

	if(cmd_cache == NULL){
		log_error(logger,"cmd_cache is NULL, ms=%d",s->ms);
		return RET_ERROR;
	}

    if (query->type == SQL_SET_NUM) {
        //这里要将set命令缓存下来
        cache_query = (packet_query*) calloc(1,sizeof(packet_query));
        if (0 != packet_query_copy(query, cache_query)) {
            log_error(logger,"copy set query failed");
            return RET_ERROR;
        }
        g_ptr_array_add(cmd_cache, cache_query);
    }
    
    //add by ybx
    if (is_not_repeatable(query->type) && query->type != SQL_USE_IN_QUERY_NUM && query->type != SQL_USE_NUM){
        cache_query = (packet_query*) calloc(1,sizeof(packet_query));
        if (0 != packet_query_copy(query, cache_query)) {
            log_error(logger,"copy set query failed");
            return RET_ERROR;
        }
        if (g_ptr_array_no_repeat_add(cmd_cache,cache_query) == 0){
	     log_error(logger,"cache_query is null");
            return RET_ERROR;
        }
    }

    if (before_ms != s->ms) {
        s->is_exec_last_use_query = 1;
    }
    ret = RET_SUCCESS;
    s->query_times++;

    return_step: return ret;
}

inline int is_read_query(int sql_num) {
    if (sql_num == SQL_UNKNOWN_NUM)
        return 2;
    if (sql_num == SQL_SELECT_NUM || sql_num == SQL_SHOW_NUM || sql_num
            == SQL_EXPLAIN_NUM || sql_num == SQL_KILL_NUM || sql_num
            == SQL_DESC_NUM || sql_num == SQL_USE_NUM || sql_num == SQL_USE_IN_QUERY_NUM || sql_num
            == SQL_PING_NUM || sql_num == SQL_STAT_NUM || sql_num
            == SQL_CHANGEUSER_NUM || sql_num == SQL_REFRESH_NUM || sql_num
            == SQL_PROCESS_INFO_NUM || sql_num == SQL_DEBUG_NUM || sql_num
            == SQL_FIELD_LIST_NUM || sql_num == SQL_PROXY_STATUS_NUM || sql_num == SQL_SET_NUM
			|| sql_num == SQL_AUTOCOMMIT_1_NUM || sql_num == SQL_LAST_INSERT_ID_NUM) {
        return 1;
    }
    if (is_not_repeatable(sql_num)){
	 return 1;
    }
    return 0;
}
inline int end_trim(unsigned char *p, int *pos, int min_pos) {
    char byte = *(p + *pos);
    int flag = 0;

    while (byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r' || byte
            == '\x0B' || byte == ';') {
        *pos = *pos - 1;
        flag = 1;
        if (*pos <= min_pos) {
            return -1;
        }
        byte = *(p + *pos);
    }
    return flag;
}
inline int start_trim(unsigned char *p, int *pos, int min_pos) {
    char byte = *(p + *pos);
    int flag = 0;
    while (byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r' || byte
            == '\x0B') {
        *pos = *pos - 1;
        flag = 1;
        if (*pos <= min_pos) {
            return -1;
        }
        byte = *(p + *pos);
    }
    return flag;
}
inline int is_autocommit(unsigned char *args, int args_len, int *v) {
    int ret = 0;
    int pos = args_len - 2;

    if (pos < 15) {
        ret = -1;
        goto return_step;
    }

    unsigned char *p = args;

    if (-1 == end_trim(p, &pos, 1)) {
        ret = -1;
        goto return_step;
    }

    unsigned char *value = p + pos;

    if (*value == '1') {
        *v = 1;
    } else if (*value == '0') {
        *v = 0;
    } else {
        ret = -1;
        goto return_step;
    }

    pos--;

    if (-1 == end_trim(p, &pos, 1)) {
        ret = -1;
        goto return_step;
    }

    value = p + pos;

    if (*value != '=') {
        ret = -1;
        goto return_step;
    }

    pos--;

    if (-1 == end_trim(p, &pos, 1)) {
        ret = -1;
        goto return_step;
    }

    int autocommit_len = 10;

    pos -= autocommit_len - 1;

    unsigned char *autocommit = p + pos;
    if (0 == my_strncasestr(autocommit, (unsigned char*) "autocommit", 10, 10,
            1)) {
        ret = -1;
        goto return_step;
    }

    pos--;

    value = p + pos;

    int session_len, session_pos, local_len, local_pos;
    unsigned char *session, *local;

    //set @@local.autocommit=; set @@session.autocommit=;
    if (*value == '.') {

        pos--;

        session_len = 7;

        session_pos = pos - session_len - 1;

        session = p + session_pos;
        if (1 == my_strncasestr(session, (unsigned char*) "session", 7, 7, 1)) {

            session_pos--;
            value = p + session_pos;
            if (*value != '@') {
                ret = -1;
                goto return_step;
            }

            session_pos--;
            value = p + session_pos;
            if (*value != '@') {
                ret = -1;
                goto return_step;
            }

            ret = 0;
            goto return_step;

        }

        local_len = 5;

        local_pos = pos - local_len - 1;

        local = p + local_pos;
        if (1 == my_strncasestr(local, (unsigned char*) "local", 5, 5, 1)) {

            local_pos--;
            value = p + local_pos;
            if (*value != '@') {
                ret = -1;
                goto return_step;
            }

            local_pos--;
            value = p + session_pos;
            if (*value != '@') {
                ret = -1;
                goto return_step;
            }

            ret = 0;
            goto return_step;

        }

        ret = -1;
        goto return_step;

    } else if (*value == '@') {
        //set @@autocommit=;
        pos--;
        value = p + pos;
        if (*value == '@') {
            ret = 0;
            goto return_step;
        } else {
            ret = -1;
            goto return_step;
        }
    } else {
        //set autocommit=; set local autocommit=; set session autocommit=;
        if (-1 == end_trim(p, &pos, 1)) {
            ret = -1;
            goto return_step;
        }

        value = p + pos;
        if (*value == 't' || *value == 'T') {

            if (pos == 2) {
                ret = 0;
                goto return_step;
            } else {
                ret = -1;
                goto return_step;
            }
        } else {
            local_len = 5;

            local_pos = pos - local_len - 1;

            if (local_pos <= 3) {
                ret = -1;
                goto return_step;
            }

            local = p + local_pos;
            if (1 == my_strncasestr(local, (unsigned char*) "local", 5, 5, 1)) {

                local_pos--;
                if (-1 == end_trim(p, &local_pos, 1)) {
                    ret = -1;
                    goto return_step;
                }

                if (local_pos == 2) {

                    ret = 0;
                    goto return_step;
                } else {
                    ret = -1;
                    goto return_step;
                }
            }

            session_len = 7;

            session_pos = pos - session_len - 1;

            if (session_pos <= 3) {
                ret = -1;
                goto return_step;
            }

            session = p + session_pos;
            if (1 == my_strncasestr(session, (unsigned char*) "session", 7, 7,
                    1)) {

                session_pos--;
                if (-1 == end_trim(p, &session_pos, 1)) {
                    ret = -1;
                    goto return_step;
                }

                if (session_pos == 2) {

                    ret = 0;
                    goto return_step;
                } else {
                    ret = -1;
                    goto return_step;
                }
            }
        }
    }

    return_step: return ret;
}

//add by ybx
inline int is_static_args(unsigned char *args, int args_len) {
    if (1 == my_strncasestr(args, (unsigned char*) "names", args_len, 5, 1)) {
        return SQL_SET_NAMES_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character_set_client", args_len, 20, 1)) {
        return SQL_SET_CHARSET_CLIENT_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character_set_connection", args_len, 24, 1)) {
        return SQL_SET_CHARSET_CONNECTION_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character_set_database", args_len, 22, 1)) {
        return SQL_SET_CHARSET_DATABASE_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character_set_results", args_len, 21, 1)) {
        return SQL_SET_CHARSET_RESULT_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character_set_server", args_len, 20, 1)) {
        return SQL_SET_CHARSET_SERVER_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "character-set-server", args_len, 20, 1)) {
        return SQL_SET_CHARSET_SERVER_1_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "collation_connection", args_len, 20, 1)) {
        return SQL_SET_COLLATION_CONNECTION_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "collation_database", args_len, 18, 1)) {
        return SQL_SET_COLLATION_DATABASE_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "collation_server", args_len, 16, 1)) {
        return SQL_SET_COLLATION_SERVER_NUM;
    }
    if (1 == my_strncasestr(args, (unsigned char*) "collation-server", args_len, 16, 1)) {
        return SQL_SET_COLLATION_SERVER_1_NUM;
    }
	if (1 == my_strncasestr(args, (unsigned char*) "sql_mode", args_len, 8, 1)) {
        return SQL_SET_SQL_MODE_NUM;
    }
	if (1 == my_strncasestr(args, (unsigned char*) "transaction isolation level", args_len, 27, 1)
		|| 1 == my_strncasestr(args, (unsigned char*) "tx_isolation", args_len, 12, 1)) {
        return SQL_SET_TRANSACTION_ISOLATION_LEVEL_NUM;
    }

    return 0;
}


inline int is_proxy_statue_cmd(unsigned char *args, int args_len, int *type) {

    int len = args_len;

    char *proxy_status = args;

    int cnt = start_trim_from_left(proxy_status, len);
    proxy_status += cnt;
    len -= cnt;

    if (my_strncasestr(proxy_status, (unsigned char*) SQL_PROXY_STATUS_TYPE_1,
            5, 5, 1) == 1) {
        *type = 1;
        return 1;
    }

    if (my_strncasestr(proxy_status, (unsigned char*) SQL_PROXY_STATUS_TYPE_2,
            5, 5, 1) == 1) {
        *type = 2;
        return 1;
    }

    if (my_strncasestr(proxy_status, (unsigned char*) SQL_PROXY_STATUS_TYPE_3,
            5, 5, 1) == 1) {
        *type = 3;
        return 1;
    }
    return 0;

}

int is_last_insert_id(unsigned char *args, int args_len) {
	int len = args_len;
	char *last_insert_id = args;

	int cnt = start_trim_from_left(last_insert_id, len);
	last_insert_id = last_insert_id + cnt;
	len -= cnt;

	if(len <= 16) {
		return 0;
	}

	if (1 != my_strncasestr(last_insert_id,
				(unsigned char*) SQL_LAST_INSERT_ID, len, 14, 1)) {
		return 0;
	}

	last_insert_id = last_insert_id + 14;

	if(*last_insert_id != '(') {
		return 0;
	}

	last_insert_id = last_insert_id + 1;
	len -= 15;

	cnt = start_trim_from_left(last_insert_id, len);
	len -= cnt;
	if(len <= 0) {
		return 0;
	}
	last_insert_id = last_insert_id + cnt;
	if(*last_insert_id != ')') {
		return 0;
	}

	return 1;
}

inline int is_designated_db(unsigned char *args, int args_len, int *type,
        char *ip, int *port) {

    int len = args_len;

    char *designated_db = args;

    int cnt = start_trim_from_left(designated_db, len);
    designated_db = designated_db + cnt;
    len -= cnt;

    if (1 == my_strncasestr(designated_db,
            (unsigned char*) SQL_DESIGNATED_DB_MASTER, 5, 5, 1)) {
        *type = 1;
        return 1;
    }

    *type = 0;

    int i;
    for (i = 0; i < len; i++) {
        if (designated_db[i] == ':')
            break;
        if (designated_db[i] == '*')
            return -1;
        ip[i] = designated_db[i];
    }
    if (i == len)
        return -1;
    ip[i] = '\0';

    int pos = ++i;
    while (designated_db[pos] >= '0' && designated_db[pos] <= '9') {
        pos++;
    }

    int p = 0;
    char v;
    int j = 1;
    for (pos--; pos >= i; pos--) {
        v = (char) (designated_db[pos]);
        if (v < '0' || v > '9')
            return -1;
        p += (v - '0') * j;
        j *= 10;
    }

    *port = p;

    return 1;

}
inline int is_select_for_update(unsigned char *args, int args_len) {
    int ret = 0;
    int pos = args_len - 2;
    if (pos <= 6) {
        ret = -1;
        goto return_step;
    }

    unsigned char *p = args;

    if (-1 == end_trim(p, &pos, 6)) {
        ret = -2;
        goto return_step;
    }
    int update_len = 6;
    pos -= update_len - 1;
    if (pos <= 6) {
        ret = -3;
        goto return_step;
    }
    unsigned char *update = p + pos;
    if (0 == my_strncasestr(update, (unsigned char*) "update", 6, 6, 1)) {
        ret = -4;
        goto return_step;
    }
    pos -= 1;
    if (0 >= start_trim(p, &pos, 6)) {
        ret = -5;
        goto return_step;
    }
    int for_len = 3;
    pos -= for_len - 1;
    if (pos <= 6) {
        ret = -6;
        goto return_step;
    }
    unsigned char *for_str = p + pos;
    if (0 == my_strncasestr(for_str, (unsigned char*) "for", 3, 3, 1)) {
        ret = -7;
        goto return_step;
    } else {
        ret = 1;
        goto return_step;
    }
    return_step: return ret;
}
inline int is_select_lock_in_share_mode(unsigned char *args, int args_len) {
    int ret = 0;
    int min_pos = 6;
    int pos = args_len - 2;
    if (pos <= min_pos) {
        ret = -1;
        goto return_step;
    }
    unsigned char *p = args;
    if (-1 == end_trim(p, &pos, 6)) {
        ret = -2;
        goto return_step;
    }
    int mode_len = 4;
    pos -= mode_len - 1;
    if (pos <= min_pos) {
        ret = -3;
        goto return_step;
        // mode
    }
    unsigned char *mode = p + pos;
    if (0 == my_strncasestr(mode, (unsigned char*) "mode", 4, 4, 1)) {
        ret = -4;
        goto return_step;
    }
    pos--;
    if (0 >= start_trim(p, &pos, 6)) {
        ret = -5;
        goto return_step;
    }
    int share_len = 5;
    pos -= share_len - 1;
    if (pos <= 6) {
        ret = -6;
        goto return_step;
    }
    unsigned char *share = p + pos;
    if (0 == my_strncasestr(share, (unsigned char*) "share", 5, 5, 1)) {
        ret = -7;
        goto return_step;
    }
    pos--;
    if (0 >= start_trim(p, &pos, 6)) {
        ret = -8;
        goto return_step;
    }
    int in_len = 2;
    pos -= in_len - 1;
    if (pos <= 6) {
        ret = -9;
        goto return_step;
    }
    unsigned char *in = p + pos;
    if (0 == my_strncasestr(in, (unsigned char*) "in", 2, 2, 1)) {
        ret = -10;
        goto return_step;
    }
    pos--;
    if (0 >= start_trim(p, &pos, 6)) {
        ret = -11;
        goto return_step;
    }
    int lock_len = 4;
    pos -= lock_len - 1;
    if (pos <= 6) {
        ret = -12;
        goto return_step;
    }
    unsigned char *lock = p + pos;
    if (0 == my_strncasestr(lock, (unsigned char*) "lock", 4, 4, 1)) {
        ret = -13;
        goto return_step;
    } else {
        ret = 1;
        goto return_step;
    }
    return_step: return ret;
}
inline int get_query_type(packet_query *query) {

    switch (query->command) {
    case '\x02':
        return SQL_USE_NUM;
    case '\x04':
        return SQL_FIELD_LIST_NUM;
    case '\x05':
        return SQL_CREATE_DB_NUM;
    case '\x06':
        return SQL_DROPD_DB_NUM;
    case '\x07':
        return SQL_REFRESH_NUM;
    case '\x09':
        return SQL_STAT_NUM;
    case '\x0a':
        return SQL_PROCESS_INFO_NUM;
    case '\x0d':
        return SQL_DEBUG_NUM;
    case '\x11':
        return SQL_CHANGEUSER_NUM;
    case '\x0e':
        return SQL_PING_NUM;
//    case '\x18':
 //       return SQL_SEND_LONG_DATA_NUM;
//    case '\x1a':
 //       return SQL_STMT_RESET_NUM;
   // case '\x1b':
    //    return SQL_SET_OPTION_NUM;
  //  case '\x1c':
   //     return SQL_STMT_FETCH_NUM;
    default:
        break;
    }

    if (query->command != '\x03' && query->command != '\x16') {
        return SQL_UNKNOWN_NUM;
    }

    if (NULL == query->args || 0 >= query->args_len)
        return SQL_UNKNOWN_NUM;

    unsigned char *p = query->args;
    int cnt = start_trim_from_left(p, query->args_len);
    int len1 = query->args_len - cnt;
    p = p + cnt;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_SELECT, len1, 6, 1)) {

		//last_insert_id
		if (1 == is_last_insert_id(p + 6 ,len1 - 6)) {
			query->is_last_insert_id = 1;
			return SQL_LAST_INSERT_ID_NUM;
		}

		return SQL_SELECT_NUM;
	}
	if (1 == my_strncasestr(p, (unsigned char*) SQL_SHOW, len1, 4, 1))
        return SQL_SHOW_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_EXPLAIN, len1, 7, 1))
        return SQL_EXPLAIN_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_KILL, len1, 4, 1))
        return SQL_KILL_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_USE, len1, 3, 1))
        return SQL_USE_IN_QUERY_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_DESC, len1, 4, 1))
        return SQL_DESC_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_CALL, len1, 4, 1))
        return SQL_CALL_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_SET, len1, 3, 1)) {
        //这里需要对autocommit做特殊处理,每个query命令的末尾没有分号，只有一条命令
        int autocommit_value;
        int is_auto = is_autocommit(p, len1, &autocommit_value);
        if (is_auto == 0 && autocommit_value == 1) {
            return SQL_AUTOCOMMIT_1_NUM;
        } else if (is_auto == 0 && autocommit_value == 0) {
            return SQL_AUTOCOMMIT_0_NUM;
        }
        //add by ybx
        len1 =len1-3;
        p = p+3;
        cnt = start_trim_from_left(p, len1);
	len1 = len1 -cnt;
	p = p+cnt;

	int is_global = 0;
	int len_tmp = 0;
	if (1 == my_strncasestr(p, "global", len1, 6, 1)) {
		is_global = 1;
		len_tmp = 6;
	}else if (1 == my_strncasestr(p, "@@global.", len1, 9, 1)) {
		is_global = 1;
		len_tmp = 9;
	}else if (1 == my_strncasestr(p, "session", len1, 7, 1)) {
		is_global = 0;
		len_tmp = 7;
	}else if (1 == my_strncasestr(p, "local", len1, 5, 1)) {
		is_global = 0;
		len_tmp = 5;
	}else if (1 == my_strncasestr(p, "@@session.", len1, 10, 1)) {
		is_global = 0;
		len_tmp = 10;
	}else if (1 == my_strncasestr(p, "@@local.", len1, 8, 1)) {
		is_global = 0;
		len_tmp = 8;
	}else if (1 == my_strncasestr(p, "@@", len1, 2, 1)) {
		is_global = 0;
		len_tmp = 2;
	}
	len1 = len1 - len_tmp;
	p = p + len_tmp;
	cnt = start_trim_from_left(p, len1);
	len1 = len1 -cnt;
	p = p+cnt;
	
	int static_value=0;
        static_value=is_static_args(p, len1);
	if (static_value != 0) {
		if(is_global == 0)
	    	return static_value;
		else 
			return static_value + 100;
	}
    return SQL_SET_NUM;
    }
    if (1 == my_strncasestr(p, (unsigned char*) SQL_BEGIN, len1, 5, 1))
        return SQL_BEGIN_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_ROLLBACK, len1, 8, 1))
        return SQL_ROLLBACK_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_START_TRANSACTION, len1, 5,
            1))
        return SQL_START_TRANSACTION_NUM;
    if (1 == my_strncasestr(p, (unsigned char*) SQL_COMMIT, len1, 6, 1))
        return SQL_COMMIT_NUM;
    // 穿透需求
    if (1 == my_strncasestr(p, (unsigned char*) SQL_DESIGNATED_DB, len1, 9, 1)) {
        if (1 == is_designated_db(p + 9, len1 - 9, &(query->designated_type),
                query->designated_db_ip, &(query->designated_port))) {
            query->is_designated_db = 1;
            return SQL_DESIGNATED_DB_NUM;
        } else {
            return SQL_UNKNOWN_NUM;
        }
    }

    // 状态查询
    if (1 == my_strncasestr(p, (unsigned char*) SQL_PROXY_STATUS, len1, 16, 1)) {
        if (1 == is_proxy_statue_cmd(p + 16, len1 - 16, &(query->status_type))) {
            query->is_proxy_status = 1;
            return SQL_PROXY_STATUS_NUM;
        } else {
            return SQL_UNKNOWN_NUM;
        }
    }

    return SQL_WRITE_NUM;
}
inline int my_strncasestr(unsigned char *str1, unsigned char *str2, int len1,
        int len2, int ignore_case) {
    if (len1 <= 0 || len2 <= 0 || len1 < len2)
        return 0;
    char c1, c2;
    int pos = 0;
    int n = len2;
    while (n > 0) {
        c1 = *(str1 + pos);
        c2 = *(str2 + pos);

        if (c1 == c2) {
            n--;
            pos++;
            continue;
        }
        if (ignore_case != 1)
            return 0;
        if ('\x41' <= c1 && c1 <= '\x7A' && '\x41' <= c2 && c2 <= '\x7A') {
            if (c1 < c2) {
                if (c1 == c2 - 32) {
                    n--;
                    pos++;
                    continue;
                }
            } else {
                if (c1 - 32 == c2) {
                    n--;
                    pos++;
                    continue;
                }
            }
        }
        return 0;
    }
    return 1;
}

network_database* network_database_create() {

    network_database *db;
    if (NULL == (db = calloc(1, sizeof(network_database)))) {
        return NULL;
    }


    return db;
}

void network_database_free(network_database *db) {

    if (NULL == db)
        return;
    free(db);
    db = NULL;
}
void conn_pool_queue_free(conn_pool_queue *q) {
    if (NULL == q)
        return;
    if (NULL != q->w_queue)
        g_queue_free(q->w_queue);
    if (NULL != q->r_queue)
        g_queue_free(q->r_queue);
    free(q);
    q = NULL;
}
conn_pool_queue* conn_pool_queue_create() {
    conn_pool_queue *q;
    if (NULL == (q = calloc(1, sizeof(conn_pool_queue))) || NULL == (q->w_queue
            = g_queue_new()) || NULL == (q->r_queue = g_queue_new())) {
        conn_pool_queue_free(q);
        return NULL;
    }
    return q;
}
extern network_socket_pool* network_socket_pool_create() {
    network_socket_pool *pool;
    if (NULL == (pool = calloc(1, sizeof(network_socket_pool)))) {
        return NULL;
    }
    if (NULL == (pool->sockets = g_queue_new())) {
        free(pool);
        pool = NULL;
        return NULL;
    }
    return pool;
}
int conn_pool_delete(network_socket *s) {
    if (s == NULL || s->p_user->d_user == NULL
            || s->p_user->d_user->username[0] == '\0') {
        log_error(logger, "s==NULL || s->p_user->d_user == NULL || s->db_user.username == \\0");
        return -1;
    }
	/*
	 !!!!!!!!! 不能这么判断 -- by liming ---!!!!!!!

	if (s->client == NULL)
	{
		log_error(logger, "s->client==NULL");
		return -1;
	}*/

    cluster *clus = s->db->clus;
    GHashTable *db_user_mapping = NULL;
    if (NULL == (db_user_mapping = g_hash_table_lookup(clus->db_conn_pools,
            s->p_user->d_user->username))) {
        log_warning(logger,"no conn pool for db_user name %s exist",s->p_user->d_user->username);
        return -1;
    }

	char tmp_buf[5];
    conn_pool_queue *q = g_hash_table_lookup(db_user_mapping, 
					get_hash_key(tmp_buf, 5, s->client_found_rows, s->client_ignore_space));
    if (q == NULL) {
        log_warning(logger,"no conn_pool for [db %s, client_found_rows %d, client_ignore_space %d] exist",
				s->current_db,  s->client_found_rows, s->client_ignore_space);
        return -1;
    }

    GQueue *queue = NULL;
    if (s->ms == MS_MASTER) {
        queue = q->w_queue;
    } else {
        queue = q->r_queue;
    }
    if (queue == NULL) {
        return -1;
    }
    int i;
    GList *node = queue->head;
    for (i = 0; i < queue->length; i++) {
        if (NULL == node) {
            log_warning(logger, "conn_pool username=%s, ms=%d, node=null, i=%d",
                    s->p_user->d_user->username, s->ms, i);
            g_queue_pop_nth(queue, i);
            i = -1;
            node = queue->head;
            continue;
        }
        network_socket *pool_s;
        if (NULL == (pool_s = node->data)) {
            log_warning(logger, "conn_pool username=%s, ms=%d, node->data=null, i=%d",
                    s->p_user->d_user->username, s->ms, i);
            g_queue_pop_nth(queue, i);
            i = -1;
            node = queue->head;
            continue;
        }
        if (pool_s == s) {
            g_queue_pop_nth(queue, i);
            return 0;
        }
        node = node->next;
    }
    log_error(logger, "db socket fd=%d doesn't in conn_pool", s->fd);
    return -1;
}

int conn_pool_add(network_socket *s) {

    if (NULL == s || s->db == NULL || s->p_user == NULL || s->p_user->d_user == NULL || s->p_user->d_user->username[0] == '\0') {
        log_error(logger, "s==NULL || s->db = NULL || s->p_user == NULL || s->p_user->d_user == NULL || s->db_user.username== \\0");
        return -1;
    }
    if (s->served_client_times
            >= s->srv->config->conn_pool_socket_max_serve_client_times) {
        log_warning(logger, "network_socket fd=%d, ms=%d, served client %d times, going to free, this message shouldn't display normally", s->fd, s->ms,s->served_client_times);
        return -1;
    }
    if (s->ms == MS_UNKNOWN) {
        log_warning(logger, "network_socket fd=%d, ms=%d ",
                s->fd, s->ms);
        return -1;
    }
    if (s->client == NULL || s->client->p_user == NULL
            || s->client->p_user->d_user == NULL || s->srv == NULL) {
        log_error(logger,"client or p_user or d_user or srv NULL");
        return -1;
    }

    if (s->client->p_user->d_user->is_old != s->srv->config->user_update_flag) {
        log_warning(logger,"s->client->p_user->d_user->is_old != s->srv->config->user_update_flag");
        return -1;
    }
    if(s->ms == MS_MASTER){
        if (s->db->is_old != s->db->clus->w_update_flag) {
            log_warning(logger,"db %s:%d is old",s->db->addr.addr_name,s->db->addr.port);
            return -1;
        }
    }else {
        if (s->db->is_old != s->db->clus->r_update_flag) {
            log_warning(logger,"db %s:%d is old",s->db->addr.addr_name,s->db->addr.port);
            return -1;
        }
    }


    network_socket_buf_reset(s);
    bzero(&(s->result), sizeof(s->result));

    db_user *d_user = s->p_user->d_user;
    GHashTable *db_name_mapping = g_hash_table_lookup(
            s->p_user->d_user->clus->db_conn_pools, d_user->username);
    if (db_name_mapping == NULL) {
        log_warning(logger,"no db_user named %s in the cluster db conn_pool",d_user->username);
        return -1;
    }

	char tmp_buf[5];
    conn_pool_queue *queue =
            g_hash_table_lookup(db_name_mapping,
					get_hash_key(tmp_buf, 5, s->client->client_found_rows, s->client->client_ignore_space));

    if (queue == NULL) {
        //当前的数据库名字对应的conn_pool_queue不存在，新建一个
        if (NULL == (queue = (conn_pool_queue*) conn_pool_queue_create())) {
            log_warning(logger,"conn_pool_queue_create() return null");
            return -1;
        }
        char *db_name = (char*)malloc(sizeof(char) * 5);
        snprintf(db_name,5,"%s",tmp_buf);
        g_hash_table_insert(db_name_mapping, db_name, queue);
    }
    if (s->ms == MS_MASTER) {
        g_queue_push_tail(queue->w_queue, s);
    } else {
        g_queue_push_tail(queue->r_queue, s);
    }
    s->is_in_pool = 1;
    s->state = STATE_READ_AUTH_RESULT;
    s->client = NULL;
    return 0;
}

network_database* load_balance(network_socket *client) {
    if (NULL == client) {
        log_error(logger, "load_balacne() client==NULL");
        return NULL;
    }
    GPtrArray *dbs;
    int t_weight = 0;
    if (client->ms == MS_MASTER) {
        dbs = client->p_user->d_user->clus->master_dbs;
    } else if (client->ms == MS_SLAVE) {
        dbs = client->p_user->d_user->clus->slave_dbs;
    } else {
        log_warning(logger, "load_balance() param ms=%d is unknown", client->ms);
        return NULL;
    }

    int len;
    len = dbs->len;
    if(len <= 0 && client->ms == MS_SLAVE) {
        dbs = client->p_user->d_user->clus->master_dbs;
        len = dbs->len;
        if(len <= 0) {
            log_warning(logger, "load_balance() dbs->len=%d <= 0", dbs->len);
            return NULL;
        }
        client->ms = MS_MASTER;
		client->is_last_query_write = 1;
		gettimeofday(&(client->write_time),0);
    }


    int i;
    network_database *cur_db = NULL;
    network_database *min_db = NULL;

    for (i = 0; i < len; i++) {
        cur_db = g_ptr_array_index(dbs, i);
        if( (client->ms == MS_MASTER && cur_db->is_old != cur_db->clus->w_update_flag) ||
              (client->ms == MS_SLAVE && cur_db->is_old != cur_db->clus->r_update_flag)  ){
            continue;
        }
        t_weight += cur_db->weight;
    }
    for (i = 0; i < len; i++) {
        cur_db = g_ptr_array_index(dbs, i);

        if(client->ms == MS_MASTER && cur_db->is_old != cur_db->clus->w_update_flag){
            log_warning(logger,"current db %s:%d is old ",cur_db->addr.addr_name,cur_db->addr.port);
            if(cur_db->cur_connected <= 0){
				log_warning(logger,"current db %s:%d will be removed and free",cur_db->addr.addr_name,cur_db->addr.port);
                remove_network_database(cur_db,cur_db->clus->master_dbs);
				network_database_free(cur_db);
                len = client->p_user->d_user->clus->master_dbs->len;
                i--;
            }
            continue;
        } else if(client->ms == MS_SLAVE && cur_db->is_old != cur_db->clus->r_update_flag){
            log_warning(logger,"current db %s:%d is old ",cur_db->addr.addr_name,cur_db->addr.port);
            if(cur_db->cur_connected <= 0){
				log_warning(logger,"current db %s:%d will be removed and free",cur_db->addr.addr_name,cur_db->addr.port);
                remove_network_database(cur_db,cur_db->clus->slave_dbs);
				network_database_free(cur_db);
                len = client->p_user->d_user->clus->slave_dbs->len;
                i--;
            }
            continue;
        }
        if(cur_db->weight == 0 && t_weight != 0){
            continue;
        }

        if (cur_db->cur_connected >= (cur_db->max_connections
                / client->srv->config->max_threads)) {
			log_warning(logger,"database(ip:%s,current_connections:%d) reach the max_connections limit(%d)",cur_db->addr.addr_name,cur_db->cur_connected,cur_db->max_connections/client->srv->config->max_threads);
            continue;
        }
        if ((client->srv->cur_time.tv_sec - cur_db->last_fail_time)
                < cur_db->time_reconnect_interval) {
            log_warning(logger,"time passed since last connect fail is less than time_reconnect_interval, skip this db");
            continue;
        }
        //加上权重
        if (NULL == min_db) {
            min_db = cur_db;
        } else {
            if(t_weight == 0){
               if(min_db->cur_connected > cur_db->cur_connected) {
                   min_db = cur_db;
               }
            } else {
               double min_v = (double)min_db->cur_connected/min_db->weight;
               double cur_v = (double)cur_db->cur_connected/cur_db->weight;
               if(min_v > cur_v) {
                   min_db = cur_db;
               }
            }

        }
    }

    //从库不可用的情况
    if (min_db == NULL && client->ms == MS_SLAVE) {

		client->ms = MS_MASTER;
		client->is_last_query_write = 1;
		gettimeofday(&(client->write_time),0);

        dbs = client->p_user->d_user->clus->master_dbs;
        t_weight = 0;
        len = dbs->len;
        for (i = 0; i < len; i++) {
            cur_db = g_ptr_array_index(dbs, i);
            if( cur_db->is_old != cur_db->clus->w_update_flag ){
                continue;
            }
            t_weight += cur_db->weight;
        }
        for (i = 0; i < len; i++) {
            cur_db = g_ptr_array_index(dbs, i);

            if (cur_db->is_old != cur_db->clus->w_update_flag){
                if(cur_db->cur_connected <= 0){
                    remove_network_database(cur_db,cur_db->clus->master_dbs);
                    len = client->p_user->d_user->clus->master_dbs->len;
                    i--;
                    continue;
                }
            }


            // 如果剩余的连接数少于或等于保留的连接数，则跳过
            if (cur_db->cur_connected + cur_db->reserved_master_connections >= cur_db->max_connections) {
                continue;
            }

            if(cur_db->weight == 0 && t_weight != 0){
                continue;
            }

            if (cur_db->cur_connected >= (cur_db->max_connections
                    / client->srv->config->max_threads)) {
                continue;
            }
            if ((client->srv->cur_time.tv_sec - cur_db->last_fail_time)
                    < cur_db->time_reconnect_interval) {
                continue;
            }
            //加上权重
            if (NULL == min_db) {
                min_db = cur_db;
            } else {
                if(t_weight == 0){
                    if(min_db->cur_connected > cur_db->cur_connected) {
                        min_db = cur_db;
                    }
                } else {
                    double min_v = (double)min_db->cur_connected/min_db->weight;
                    double cur_v = (double)cur_db->cur_connected/cur_db->weight;
                    if(min_v > cur_v) {
                        min_db = cur_db;
                    }
                }
            }
        }

    }
    return min_db;
}

network_socket* conn_pool_network_socket_connect(network_server *srv,
        network_socket *client) {
    if (NULL == srv || NULL == client) {
        log_error(logger, "conn_pool_network_socket_connect srv==NULL || client==NULL");
        return NULL;
    }
    network_database *db;
    network_socket *s = NULL;

    if (client->p_user->d_user == NULL) {
        log_warning(logger,"client->p_user %s ->d_user is NULL",client->p_user->username);
        return NULL;
    }

    while (1) {
        if (NULL == (db = load_balance(client))) {
            log_warning(logger, "load_balance() return null ms=%d maybe reach the max connections", client->ms);
            return NULL;
        }

        //log_debug(logger, "fd[%d] select db[%s:%d], m/s?[%d], cur_conns[%d], max_conns[%d], reserved_master_conns[%d]",
		//	client->fd, db->addr.addr_name, db->addr.port, db->ms, db->cur_connected, db->max_connections, db->reserved_master_connections);

        //失败重连
        int i;
        int reconnect_times = srv->config->reconnect_times;
        for (i = 0; i < reconnect_times; i++) {
            if (NULL == (s = network_socket_get(srv->sockets_pool, 1))) {
                return NULL;
            }
            if (0 != connect_nonblock(s->fd,
                    (struct sockaddr *) &db->addr.addr_ip, db->addr.addr_len,
                    db->connect_timeout)) {
                log_warning(logger, "can't connect to %s:%d, errno=%d, error: %s, maybe mysqld hasn't been started reconnect time=%d", db->addr.addr_name, db->addr.port, errno, strerror(errno), i);
                network_socket_put_back(s);
                continue;
            }
            db->cur_connected++;
            db->last_fail_time = 0;
            s->db = db;
            s->ms = client->ms;
            s->state = STATE_CONNECTED_SERVER;

            int sock_len = sizeof(s->addr);
            int sock_ret = 0;
            sock_ret = getsockname(s->fd,(struct sockaddr*)&(s->addr),&sock_len);
            if(sock_ret != 0){
                log_warning(logger,"getsockname failed");
                close(s->fd);
                return NULL;
            }

            char* s_ip = (char*)inet_ntoa(s->addr.sin_addr);
            if(s_ip != NULL) {
                snprintf(s->ip,20,"%s",s_ip);
            } else {
                s->ip[0] = '\0';
            }

            s->port = s->addr.sin_port;

            return s;
        }
        db->last_fail_time = srv->cur_time.tv_sec;
    }
    return NULL;
}
inline network_socket* network_socket_pool_get(network_socket_pool *pool) {
    if (NULL == pool) {
        log_error(logger, " pool == NULL");
        return NULL;
    }
    if (0 == pool->sockets->length)
        return NULL;
    network_socket *s = NULL;
    s = g_queue_pop_head(pool->sockets);
    s->use_times++;
    return s;
}

inline network_socket* conn_pool_get(network_socket *client) {

   
    if (client == NULL)
        return NULL;
    product_user *p_user = client->p_user;
    db_user *d_user = p_user->d_user;

    if (d_user == NULL) {
        log_warning(logger,"product_user %s d_user is NULL",client->p_user->username);
        return NULL;
    }

    cluster *clus = d_user->clus;

    GHashTable *db_user_mapping;

    if (NULL == (db_user_mapping = g_hash_table_lookup(clus->db_conn_pools,
            d_user->username))) {
        log_warning(logger,"no conn_pool for d_user name %s exists",d_user->username);
        return NULL;
    }

    conn_pool_queue *q;
	char tmp_buf[5];
    if (NULL == (q = g_hash_table_lookup(db_user_mapping, get_hash_key(tmp_buf, 5, client->client_found_rows, client->client_ignore_space) ))) {
        return NULL;
    }

    network_socket *s = NULL;
    if (client->ms == MS_MASTER) {
        if (0 == q->w_queue->length) {
            return NULL;
        }
        while(q->w_queue->length > 0){
            s = g_queue_pop_head(q->w_queue);
            if(s == NULL){
                continue;
            }
            if(s->db == NULL || (s->db != NULL && s->db->is_old != s->db->clus->w_update_flag)){
                s->is_in_pool = 0;
                server_free(s,0);
                s = NULL;
                continue;
            }
            break;
        }

    } else if (client->ms == MS_SLAVE) {
        if (0 == q->r_queue->length) {
            return NULL;
        }
        while(q->r_queue->length > 0){
            s = g_queue_pop_head(q->r_queue);
            if(s == NULL){
                continue;
            }
            if(s->db == NULL || (s->db != NULL && s->db->is_old != s->db->clus->r_update_flag)){
                s->is_in_pool = 0;
                server_free(s,0);
                s = NULL;
                continue;
            }
            break;
        }
    } else {
        log_warning(logger, "conn_pool_get ms != MS_MASTER && ms != MS_SLAVE");
        return NULL;
    }
    if (s == NULL) {
        log_error(logger, "conn_pool_get g_queue_pop_head return network_socket==NULL user=%s, ms=%d",
                p_user->username, client->ms);
        return NULL;
    }
    s->is_in_pool = 0;
    return s;
}

db_user* db_user_create() {

    db_user *user;
    if (NULL == (user = calloc(1, sizeof(db_user)))) {
        return NULL;
    }
    return user;
}
product_user* product_user_create() {

    product_user *user;
    if (NULL == (user = calloc(1, sizeof(product_user)))) {
        return NULL;
    }
    return user;
}
extern network_socket* network_socket_get(network_socket_pool *pool,
        int is_server) {
    if (NULL == pool) {
        log_error(logger, "pool is null");
        return NULL;
    }
    network_socket *s = NULL;
    if (NULL == (s = network_socket_pool_get(pool))) {
        if (NULL == (s = network_socket_create())) {
            return NULL;
        }
    }
    if (is_server == 1) {
        if (0 > (s->fd = socket(AF_INET, SOCK_STREAM, 0))) {
            log_error(logger, "socket(AF_INET, SOCK_STREAM, 0) failed, errno=%d, error:%s", errno, strerror(errno));
            network_socket_put_back(s);
            return NULL;
        }
    } else {
        s->is_client_socket = 1;
        s->packet_id = 0;
        s->start_time = pool->srv->cur_time;
    }
    s->srv = pool->srv;
    return s;
}
inline void clear_server_socket(network_socket *server) {
    if (1 == is_db_socket_reuseable(server)) {
        if (0 != conn_pool_add(server)) {
            log_warning(logger, "add clean db socket to conn_pool failed db fd=%d", server->fd);
            //FIXME client_free?
            server_free(server, 0);
        }
    } else {
        if (server->served_client_times
                >= server->srv->config->conn_pool_socket_max_serve_client_times) {
            log_load(logger, "network_socket fd=%d ms=%d served client %d times, going to free",
                    server->fd, server->ms,server->served_client_times);
        }
        server_free(server, 0);
    }
    server = NULL;
}

network_socket* network_socket_get_db_socket(network_server *srv,
        network_socket *client, poll *poll) {
    if (srv == NULL || client == NULL || poll == NULL) {
        log_error(logger, "srv == NULL || client == NULL || poll == NULL");
        return NULL;
    }

    network_socket *server = client->server;

    guint db_key = 0;
    if (server != NULL) {
        db_key = client->db->key;
    }

    // 这里处理穿透需求
    if (client->query.is_designated_db == 1) {
        //指定走主库
        if (client->query.designated_type == 1) {
            if (server != NULL) {
                if (server->ms == MS_MASTER) {
                    client->query.is_designated_db = 0;
                    goto fetch_status;
                } else {
                    goto normal_status;
                }
            }
            if (client->p_user->is_old != srv->config->user_update_flag) {
                return NULL;
            }
            if(client->p_user->d_user != NULL && client->p_user->d_user->is_old != srv->config->user_update_flag){
                return NULL;
            }
            GHashTable *db_user_mapping;

            if (NULL == (db_user_mapping = g_hash_table_lookup(
                    client->p_user->d_user->clus->db_conn_pools,
                    client->p_user->d_user->username))) {
                log_warning(logger,"no conn_pool for d_suer name %s exists",client->p_user->d_user->username);
                return NULL;
            }

			char tmp_buf[5];
            conn_pool_queue *q = g_hash_table_lookup(db_user_mapping,
               get_hash_key(tmp_buf, 5, client->client_found_rows, client->client_ignore_space));
            if (NULL != q && 0 != q->w_queue->length) {
                server = g_queue_pop_head(q->w_queue);
                server->ms = MS_MASTER;
                client->db = server->db;
                server->is_in_pool = 0;
                reset_client_sending_cmd_status(client);
                goto fetch_status;
            } else {
                //没有当前数据库连接池时重新建立一个新的连接
                server = connect_to_server_cmp(
                        client->p_user->d_user->clus->master_dbs, 0, client);
                if (server == NULL)
                    return NULL;
                else {
                    server->ms = MS_MASTER;
                    goto fetch_status;
                }
            }

        }

        if (server != NULL) {
            //穿透指定的服务器就是当前的服务器
            if (0 == strncmp(server->db->addr.addr_name,
                    client->query.designated_db_ip, 20)
                    && server->db->addr.port == client->query.designated_port) {
                client->query.is_designated_db = 0;
                goto fetch_status;
            } else {
                if (client->p_user->is_old != srv->config->user_update_flag) {
                    clear_server_socket(server);
                    client->server = NULL;
                    return NULL;
                }
                clear_server_socket(server);
                client->server = NULL;
            }
        }

        if (client->p_user->is_old != srv->config->user_update_flag) {
            return NULL;
        }
        if(client->p_user->d_user != NULL && client->p_user->d_user->is_old != srv->config->user_update_flag){
            return NULL;
        }

        GHashTable *db_user_mapping;

        if (NULL == (db_user_mapping = g_hash_table_lookup(
                client->p_user->d_user->clus->db_conn_pools,
                client->p_user->d_user->username))) {
            log_warning(logger,"no conn_pool for d_user name %s exists",client->p_user->d_user->username);
            return NULL;
        }

        conn_pool_queue *q;
		char tmp_buf[5];
        if (NULL != (q = g_hash_table_lookup(db_user_mapping,
                get_hash_key(tmp_buf, 5, client->client_found_rows, client->client_ignore_space) ))) {
            server = get_network_socket_from_queue(q->w_queue, 1,
                    client->query.designated_db_ip,
                    client->query.designated_port);
            if (server != NULL) {

                client->ms = MS_MASTER;
                client->is_last_query_write = 1;
                gettimeofday(&(client->write_time), 0);
                server->ms = MS_MASTER;
                client->db = server->db;
                server->p_user = client->p_user;
                reset_client_sending_cmd_status(client);
                goto fetch_status;
            }
            server = get_network_socket_from_queue(q->r_queue, 1,
                    client->query.designated_db_ip,
                    client->query.designated_port);
            if (server != NULL) {
                client->ms = MS_SLAVE;
                server->ms = MS_SLAVE;
                client->db = server->db;
                server->p_user = client->p_user;
                reset_client_sending_cmd_status(client);
                goto fetch_status;
            }
        }

        GPtrArray *dbs = client->p_user->d_user->clus->master_dbs;
        server = connect_to_server_cmp(dbs, 1, client);
        if (server != NULL) {
            server->ms = MS_MASTER;
            client->is_last_query_write = 1;
            gettimeofday(&(client->write_time), 0);
            client->ms = MS_MASTER;
            server->p_user = client->p_user;
            goto fetch_status;
        }

        dbs = client->p_user->d_user->clus->slave_dbs;
        server = connect_to_server_cmp(dbs, 1, client);
        if (server != NULL) {
            server->ms = MS_SLAVE;
            client->ms = MS_SLAVE;
            server->p_user = client->p_user;
            goto fetch_status;
        }
        return NULL;

    }



    if (NULL != server) {

        normal_status: if (client->ms == server->ms) {
            goto fetch_status;
        }
        if (client->p_user->is_old != srv->config->user_update_flag) {
            clear_server_socket(server);
            client->server = NULL;
            return NULL;
        }
        clear_server_socket(server);
        client->server = NULL;
    }

    if (client->p_user->is_old != srv->config->user_update_flag) {
        return NULL;
    }
    if(client->p_user->d_user != NULL && client->p_user->d_user->is_old != srv->config->user_update_flag){
        return NULL;
    }

    //在这里调用二次开发钩子
    int hookIndex;
    for (hookIndex = 0; hookIndex < srv->config->h_array->so_nums; hookIndex++) {
        server = NULL;
        int ret = call_hook_func(hookIndex,4,&server,-1);
        if (ret == 0 && server != NULL) {
            goto fetch_status;
        }
    }
    if (NULL != (server = conn_pool_get(client))) {
        server->served_client_times++;
        server->p_user = client->p_user;
        client->db = server->db;
        goto fetch_status;
    }
    if (NULL == (server = conn_pool_network_socket_connect(srv, client))) {
        return NULL;
    }

   

    server->p_user = client->p_user;
    client->db = server->db;

    if (server->fd < 0 || server->fd >= CONFIG_MPL_EPOLL_MAX_SIZE) {
        log_warning(logger, "server->fd=%d < 0 || > CONFIG_MPL_EPOLL_MAX_SIZE=%d", server->fd, CONFIG_MPL_EPOLL_MAX_SIZE);
        server_free(server, 0);
        return NULL;
    }
    poll->fd_mapping[server->fd] = server;
    poll_events_add(poll, server, EPOLLIN);
    server->srv = srv;
    server->poll = poll;
    server->last_active_time = srv->cur_time.tv_sec;
    server->served_client_times = 1;

    fetch_status:

    if(server->db == NULL){
        log_error(logger,"server->db is NULL");
        return NULL;
    }

    server->client = client;
    client->server = server;

    snprintf(server->current_db, MAX_DEFAULT_DB_NAME_LEN,"%s", client->current_db);


    server->has_call_sql = client->has_call_sql;
    server->has_set_sql = client->has_set_sql;
    server->has_use_sql = client->has_use_sql;
    server->has_changeuser_sql = client->has_changeuser_sql;

    if (db_key != client->db->key || client->ms != client->before_ms) {

        if (client->ms == MS_MASTER) {
            snprintf(client->dbip_and_user_and_userip, 3, "M:");
        } else {
            snprintf(client->dbip_and_user_and_userip, 3, "S:");
        }

        snprintf(client->dbip_and_user_and_userip + 2,MAX_STATUS_TYPE_2_KEY - 2,"%s#%s#%s",client->db->addr.addr_name,
                client->p_user->username,client->ip);

        client->key_type2 = str_hash(client->dbip_and_user_and_userip);
    }

    return server;
}

inline int network_queue_send_append(byte_array *send_buf,
        const unsigned char *data, int len, unsigned char packet_id,
        int append_data_later) {
    if (send_buf == NULL || len <= 0
            || (data == NULL && append_data_later == 0)) {
        log_error(logger, "send_buf==NULL||len=%d<= 0 ||(data == null&& append_data_later=%d == 0)",
                len, append_data_later);
        return RET_ERROR;
    }
    unsigned char header[4];
    header[0] = (len >> 0) & 0xFF;
    header[1] = (len >> 8) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = packet_id; // out of 255 ??

    if (0 != byte_array_append_len(send_buf, header, 4)) {
        return RET_NO_MEMORY;
    }
    if (append_data_later == 0) {
        if (0 != byte_array_append_len(send_buf, data, len)) {
            return RET_NO_MEMORY;
        }
    }
    return RET_SUCCESS;
}


void watcher(zhandle_t *zh, int type, int state, const char *path,
        void* context) {

    if (type == ZOO_CHILD_EVENT && state == ZOO_CONNECTED_STATE) {

        if(path == NULL){
            log_error(logger,"zk path is NULL");
            return;
        }

		char* db_data = NULL;

		db_data = (char*) malloc(sizeof(char)*1024*32);
		if(db_data == NULL) {
			log_error(logger,"malloc memory failed, need %d bytes, no enough memory", sizeof(char)*1024*32);
			return;
		}

		int db_offset = 0;	

		memset(db_data,0,1024*32);

		network_server_config *config =
			(network_server_config*) zoo_get_context(zh);
		db_group_info *bd = g_hash_table_lookup(config->basic_db_info, path);
        if (bd == NULL) {
            log_warning(logger,"db_goup_info is NULL");
			free(db_data);
            return;
        }

        network_database *basic_db = bd->basic_db;

        int zk_ret;
        struct String_vector child_paths;
        zk_ret = zoo_get_children(config->zh, path, 1, &child_paths);

        if (zk_ret != ZOK) {
            const char *zk_error = zerror(zk_ret);
            log_warning(logger," zk node %s, error %s", path, zk_error);
			free(db_data);
            return;
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

            snprintf(child_path, f_len,"%s", path);
            child_path[f_len - 1] = '/';
            snprintf(child_path + f_len, c_len,"%s", cp);

            memset(buffer, 0, MAX_ZOOKEEPER_PATH_LEN);
            len = MAX_ZOOKEEPER_PATH_LEN;

            zk_ret = zoo_get(zh, child_path, 0, buffer, &len, NULL);
            if (zk_ret != ZOK) {
                const char *zk_error = zerror(zk_ret);
                log_warning(logger," zk node %s error %s", child_path, zk_error);
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
			free(db_data);
            return;
		}

		FILE *local_conf_file;
        char conf_file_name[MAX_FILE_NAME_LEN];
        snprintf(conf_file_name, MAX_FILE_NAME_LEN, "%s/%d.conf",
                config->zk_conf_dir, bd->array_index);


        int conf_file_fd = open(conf_file_name,O_RDONLY);
        if(conf_file_fd == -1) {
            log_warning(logger,"open zk local conf file failed file_name %s",
                    conf_file_name);
			free(db_data);
            return;
        }

        int lock_ret = flock(conf_file_fd,LOCK_EX);
        if(lock_ret == -1) {
            log_warning(logger,"lock_ex on file %s failed!",conf_file_name);
            close(conf_file_fd);
			free(db_data);
            return;
        }

        if (NULL == (local_conf_file = fopen(conf_file_name, "w+"))) {
            log_warning(logger,"open zk local conf file failed file_name %s",
                    conf_file_name);

            flock(conf_file_fd,LOCK_UN);
            close(conf_file_fd);
			free(db_data);
            return;
        }

		put_ret = fputs(db_data, local_conf_file);
		if (put_ret == EOF) {
			log_warning(logger,"fputs failed");
		}


        if (EOF == fclose(local_conf_file)) {
            log_warning(logger,"flcose failed, filename=%s", conf_file_name);
        }

        flock(conf_file_fd,LOCK_UN);
        close(conf_file_fd);
		free(db_data);
        log_load(logger,"get the new db info from zookeeper zk_path %s",path);
    }
}

int init_zookeeper(network_server_config *config, char *zk_host,
        char *zk_log_file,int is_watch) {

    if (config == NULL || config->zh != NULL) {
        printf("zh not NULL");
        return -1;
    }
    zoo_set_debug_level(ZOO_LOG_LEVEL_WARN);


    if(is_watch == 1) {
        config->zh = zookeeper_init(zk_host, watcher, config->zk_timeout, NULL,
                0, 0);
    } else {
        config->zh = zookeeper_init(zk_host, NULL, config->zk_timeout, NULL,
                0, 0);
    }
    if (!config->zh) {
        return -1;
    }

    FILE *log_stream = fopen(zk_log_file, "a+");
    if (log_stream == NULL) {
        printf("%s:%s:%d open zk_log_file failed", __FILE__,
                __PRETTY_FUNCTION__, __LINE__);
        return -1;
    }
    zoo_set_log_stream(log_stream);

    zoo_set_context(config->zh, config);
    return 0;

}
