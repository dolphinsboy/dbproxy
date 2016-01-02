#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <glib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "global.h"
#include "Epoll.h"
#include "log.h"
#include "array.h"
#include "zookeeper.h"

#define NETWORK_SOCKET_MAX_USE_TIMES 10000

#define SEND_BUF_DEFAULT_SIZE 51200
#define SELF_BUF_DEFAULT_SIZE 4096

#define PACKET_HEADER_LEN 4
#define PACKET_LEN_MAX 0x00ffffff
#define PACKET_LEN_UNSET 0xffffffff

#define MS_UNKNOWN 0
#define	MS_MASTER 1
#define MS_SLAVE 2

#define SQL_SELECT "select"
#define SQL_SHOW "show"
#define SQL_EXPLAIN "explain"
#define SQL_KILL "kill"
#define SQL_USE "use"
#define SQL_DESC "desc"
#define SQL_CALL "call"
#define SQL_SET "set"
#define SQL_AUTOCOMMIT "autocommit"
#define SQL_BEGIN "begin"
#define SQL_ROLLBACK "rollback"
#define SQL_START_TRANSACTION "start"
#define SQL_COMMIT "commit"
#define SQL_PROXY_STATUS "checkproxystatus"
#define SQL_PROXY_STATUS_TYPE_1 "type1"
#define SQL_PROXY_STATUS_TYPE_2 "type2"
#define SQL_PROXY_STATUS_TYPE_3 "type3"
#define SQL_DESIGNATED_DB "dbconnect"
#define SQL_DESIGNATED_DB_MASTER "master"
#define SQL_LAST_INSERT_ID "last_insert_id"

#define SQL_UNKNOWN_NUM 0
#define SQL_SELECT_NUM 1
#define SQL_SHOW_NUM 2
#define SQL_EXPLAIN_NUM 3
#define SQL_KILL_NUM 4
#define SQL_USE_NUM 5
#define SQL_USE_IN_QUERY_NUM 32
#define SQL_DESC_NUM 6
#define SQL_CALL_NUM 7
#define SQL_SET_NUM 8
#define SQL_CHANGEUSER_NUM 9
#define SQL_PING_NUM 10
#define SQL_STAT_NUM 11

#define SQL_SELECT_FOR_UPDATE_NUM 12
#define SQL_SELECT_LOCK_IN_SHARE_MODE_NUM 13

#define SQL_AUTOCOMMIT_1_NUM 14
#define SQL_BEGIN_NUM 15
#define SQL_START_TRANSACTION_NUM 16
#define SQL_ROLLBACK_NUM 17
#define SQL_COMMIT_NUM 18

#define SQL_CREATE_DB_NUM 19
#define SQL_DROPD_DB_NUM 20
#define SQL_REFRESH_NUM 21
#define SQL_PROCESS_INFO_NUM 22
#define SQL_DEBUG_NUM 23
//#define SQL_SEND_LONG_DATA_NUM 24
#define SQL_STMT_RESET_NUM 25
#define SQL_SET_OPTION_NUM 26
#define SQL_STMT_FETCH_NUM 27
#define SQL_FIELD_LIST_NUM 28

#define SQL_AUTOCOMMIT_0_NUM 29

#define SQL_PROXY_STATUS_NUM 30
#define SQL_DESIGNATED_DB_NUM 31
#define SQL_LAST_INSERT_ID_NUM 33

//add by ybx
//add by yinboxue
#define SQL_SET_NAMES_NUM 34
#define SQL_SET_GLOBAL_NAMES_NUM 134
#define SQL_SET_CHARSET_CLIENT_NUM 35
#define SQL_SET_GLOBAL_CHARSET_CLIENT_NUM 135
#define SQL_SET_CHARSET_CONNECTION_NUM 36
#define SQL_SET_GLOBAL_CHARSET_CONNECTION_NUM 136
#define SQL_SET_CHARSET_DATABASE_NUM 37
#define SQL_SET_GLOBAL_CHARSET_DATABASE_NUM 137
#define SQL_SET_CHARSET_RESULT_NUM 38
#define SQL_SET_GLOBAL_CHARSET_RESULT_NUM 138
#define SQL_SET_CHARSET_SERVER_NUM 39
#define SQL_SET_GLOBAL_CHARSET_SERVER_NUM 139
#define SQL_SET_CHARSET_SERVER_1_NUM 40
#define SQL_SET_GLOBAL_CHARSET_SERVER_1_NUM 140
#define SQL_SET_COLLATION_CONNECTION_NUM 41
#define SQL_SET_GLOBAL_COLLATION_CONNECTION_NUM 141
#define SQL_SET_COLLATION_DATABASE_NUM 42
#define SQL_SET_GLOBAL_COLLATION_DATABASE_NUM 142
#define SQL_SET_COLLATION_SERVER_NUM 43
#define SQL_SET_GLOBAL_COLLATION_SERVER_NUM 143
#define SQL_SET_COLLATION_SERVER_1_NUM 44
#define SQL_SET_GLOBAL_COLLATION_SERVER_1_NUM 144
#define SQL_SET_SQL_MODE_NUM 45
#define SQL_SET_GLOBAL_SQL_MODE_NUM 145
#define SQL_SET_TRANSACTION_ISOLATION_LEVEL_NUM 46
#define SQL_SET_GLOBAL_TRANSACTION_ISOLATION_LEVEL_NUM 146
#define SQL_WRITE_NUM 255

/**
 * @brief ���ӳ�������������ݿ����ӵĶ���
 */
typedef struct {
    /**< �������*/
	GQueue *w_queue;
	/**< �ӿ����*/
	GQueue *r_queue;
} conn_pool_queue;

/**
 * @brief �������ַ�ķ�װ
 */
typedef struct {
    /**< sockaddr_in�ṹ�ĵ�ַ*/
	struct sockaddr_in addr_ip;
	/**< ip��ַ�ַ���*/
	char addr_name[MAX_IP_LEN];
	/**< ��ַ����*/
	int addr_len;
	/**< �˿�*/
	int port;
} network_address;

/**
 * @brief ��֤IP
 */
typedef struct {
    /**< IP��ַ*/
	struct in_addr addr;
} auth_ip;

/**
 * @brief ��Ⱥ��Ϣ
 */
struct _cluster {
    /**< ��Ⱥ������ */
	char cluster_name[MAX_CLUSTER_NAME_LEN];
	/**< �˼�Ⱥ�е����� */
	GPtrArray *master_dbs;
	/**< �˼�Ⱥ�еĴӿ� */
	GPtrArray *slave_dbs;
	/**< ���ӳ�
	 * �˴���һ����ϣ��keyΪ���ݿ��û�����valueΪ��һ����ϣ����keyΪ���ݿ�����֣�valueΪָ��conn_pool_queue�ṹ���ָ��
	 */
	GHashTable *db_conn_pools;
	/**<
	 * ������±�ʾ,���и�������ʱ�����ֶμ�1
	 */
	int w_update_flag;
	/**<
	 * �ӿ���±�ʾ,���и�������ʱ�����ֶμ�1
	 */
	int r_update_flag;
};
typedef struct _cluster cluster;


/**
 * @brief ���ݿ��û���
 */
typedef struct _db_user {
    /**< �û��� */
	char username[MAX_USERNAME_LEN];
	/**< ���� */
	char password[MAX_PASSWORD_LEN];
	/**< �����ַ��� */
	unsigned char scramble_password[21];
	/**< �����ַ����ĳ��� */
	int scramble_len;
	/**< ���û������������Ӽ�Ⱥ */
	cluster *clus;
	/**< Ĭ�����ݿ� */
	char default_db[MAX_DEFAULT_DB_NAME_LEN];
	/**< Ĭ���ַ��� */
	unsigned char default_charset;
	/**< ��ǰʹ�ô��û����Ŀͻ��������� */
	int current_connections;
	/**< ��ʾ���û����Ƿ��Ǿ��û��� */
	int is_old;
} db_user;

/**
 * @brief �����ݿ�������ķ�װ
 */
struct _network_database {
    /**< �����ݿ�������������ļ�Ⱥ */
	cluster *clus;
	/**< �����ݿ������������ */
	char host_name[MAX_HOST_NAME_LEN];
	/**< ��Ӧ��network_address�ṹ�壬��װ�˵�ַ���˿ڵ���Ϣ */
	network_address addr;
	/**< �����ݿ�������������ӵ���������� */
	guint max_connections;
	/**< �����ݿ�������������ӵ���С������ */
	guint min_connections;
	/**< �������ݿ��������Ϊmasterʱ�������ǰ������С�ڴ˱�����������������slave����ռ�ñ�master������ */
	guint reserved_master_connections;
	/**< �����ļ���������GROUP */
	char group_name[MAX_GROUP_LEN];
	/**< ����ʱ�ĳ�ʱʱ�� */
	int connect_timeout;
	/**< ʧ��������ʱ���� */
	int time_reconnect_interval;
	/**< ��һ��ʧЧ��ʱ�� */
	time_t last_fail_time;
	/**< ��ǰ������ */
	int cur_connected;
	/**< ��ʾ�����⻹�Ǵӿ� */
	int ms;
	/**< Ȩ�� */
	int weight;
	/**< ��ʾ�Ƿ�Ϊ�ɵ����ݿ������ */
	int is_old;
	/**< ������Ӧ��zookeeper·��*/
	char zk_path[MAX_ZOOKEEPER_PATH_LEN];
	/**< �����ݿ��IP��ϣ�Ľ��������״̬��ѯ */
	guint key;
};
typedef struct _network_database network_database;

/**
 * @brief �Բ�Ʒ���û��ķ�װ
 */
struct _product_user {
	/**< �û��� */
	char username[MAX_USERNAME_LEN];
	/**< ���� */
	char password[MAX_PASSWORD_LEN];
	/**< �����ַ��� */
	unsigned char scramble_password[21];
	/**< �����ַ����ĳ��� */
	int scramble_len;
	/**< ��˲�Ʒ���û�����Ӧ�����ݿ��û��� */
	db_user *d_user;
	/**< ��ǰ��Ʒ���û�������ʹ�õ�������ݿ������� */
	int max_connections;
	/**< ��ǰʹ�ô��û�����¼��proxy�Ŀͻ�����Ŀ */
	int current_connections;
	/**< ��ʾ���û����Ƿ��Ǿɵ� */
	int is_old;
	/**< ����û�����صľֲ���ȨIP */
	GPtrArray *auth_ips;
};
typedef struct _product_user product_user;

/**
 * @brief ����״̬��ѯ����װ�����ݿ��IP�Ͷ�Ӧ��������
 */
struct _db_ip_key{
    /**< ������ */
	int use_num;
	/**< ��network_database�ṹ���е�key�ֶζ�Ӧ�����ڱ�ʾ���ݿ� */
	guint key;
	/**< ���ݿ��IP */
	char db_ip[MAX_IP_LEN];
};
typedef struct _db_ip_key db_ip_key;

/**
 * @brief ��װ�����û���+ip��ص�״̬��ѯ����
 */
struct _status_user_and_ip {
    /**< ���ڱ�ʾ�����ڴ��е��ڴ���Ƿ��б�ʹ�� */
	int is_used;
	/**< ���ڶ�λ��key */
	guint key;
	/**< �û���+ip */
	char username_and_ip[MAX_STATUS_TYPE_1_KEY];
	/**< ��proxy�������� */
	int proxy_connections;
	/**< �����ݿ�������� */
	int db_connections;
	/**< ��Ӧ��������Ϣ */
//	db_ip_key master_ips[MAX_MASTER_IPS];
	/**< ��Ӧ�Ĵӿ���Ϣ */
//	db_ip_key slave_ips[MAX_SLAVE_IPS];
	/**< ���̺� */
	char pid[10];


	char masters[MAX_STATUS_IPS_LEN];

	char slaves[MAX_STATUS_IPS_LEN];

	char cur_time[MAX_STATUS_TIME_LEN];

};
typedef struct _status_user_and_ip status_user_and_ip;

/**
 * @brief ��װ�������ݿ�IP���û�����ص�״̬��ѯ����
 */
struct _status_dbip_and_user {
    /**< ���ڱ�ʾ�����ڴ��е��ڴ���Ƿ��б�ʹ�� */
	int is_used;
	/**< ���ڶ�λ��key */
	guint key;
	/**< ���ݿ�IP+�û���+�û�IP */
	char dbip_and_user_and_userip[MAX_STATUS_TYPE_2_KEY];
	/**< ������ */
	int connection_num;
	/**< ���̺� */
	char pid[10];
	char cur_time[MAX_STATUS_TIME_LEN];
};
typedef struct _status_dbip_and_user status_dbip_and_user;

/**
 * @brief ��װ����MySQL Proxy Layer������ص�״̬��ѯ����
 */
struct _status_mysql_proxy_layer {
    /**< ��ǰ�ӽ�����ʹ�õ��ڴ��� */
    char vmsize[MAX_PROC_STATUS_LEN];
    /**< ÿһ�����ӳ��е������� */
    char conn_pool_stat[MAX_DB_USER_NUM*MAX_DB_NUM*MAX_PROC_CONN_LEN*2];
    /**< network_socket���ӳ��е������� */
	int network_socket_pool_num;
	/**< ʱ��� */
	char cur_time[MAX_STATUS_TIME_LEN];
	char pid[10];
};
typedef struct _status_mysql_proxy_layer status_mysql_proxy_layer;


struct _status_mmap_flag {
    int mmap_flag;
};
typedef struct _status_mmap_flag status_mmap_flag;


typedef struct _network_socket network_socket;
typedef struct _network_server network_server;

/**
 * @brief ��MySQL�������͵Ķ���
 */
enum enum_field_types {
	MYSQL_TYPE_DECIMAL,          //!< MYSQL_TYPE_DECIMAL
	MYSQL_TYPE_TINY,             //!< MYSQL_TYPE_TINY
	MYSQL_TYPE_SHORT,            //!< MYSQL_TYPE_SHORT
	MYSQL_TYPE_LONG,             //!< MYSQL_TYPE_LONG
	MYSQL_TYPE_FLOAT,            //!< MYSQL_TYPE_FLOAT
	MYSQL_TYPE_DOUBLE,           //!< MYSQL_TYPE_DOUBLE
	MYSQL_TYPE_NULL,             //!< MYSQL_TYPE_NULL
	MYSQL_TYPE_TIMESTAMP,        //!< MYSQL_TYPE_TIMESTAMP
	MYSQL_TYPE_LONGLONG,         //!< MYSQL_TYPE_LONGLONG
	MYSQL_TYPE_INT24,            //!< MYSQL_TYPE_INT24
	MYSQL_TYPE_DATE,             //!< MYSQL_TYPE_DATE
	MYSQL_TYPE_TIME,             //!< MYSQL_TYPE_TIME
	MYSQL_TYPE_DATETIME,         //!< MYSQL_TYPE_DATETIME
	MYSQL_TYPE_YEAR,             //!< MYSQL_TYPE_YEAR
	MYSQL_TYPE_NEWDATE,          //!< MYSQL_TYPE_NEWDATE
	MYSQL_TYPE_VARCHAR,          //!< MYSQL_TYPE_VARCHAR
	MYSQL_TYPE_BIT,              //!< MYSQL_TYPE_BIT
	MYSQL_TYPE_NEWDECIMAL = 246, //!< MYSQL_TYPE_NEWDECIMAL
	MYSQL_TYPE_ENUM = 247,       //!< MYSQL_TYPE_ENUM
	MYSQL_TYPE_SET = 248,        //!< MYSQL_TYPE_SET
	MYSQL_TYPE_TINY_BLOB = 249,  //!< MYSQL_TYPE_TINY_BLOB
	MYSQL_TYPE_MEDIUM_BLOB = 250,//!< MYSQL_TYPE_MEDIUM_BLOB
	MYSQL_TYPE_LONG_BLOB = 251,  //!< MYSQL_TYPE_LONG_BLOB
	MYSQL_TYPE_BLOB = 252,       //!< MYSQL_TYPE_BLOB
	MYSQL_TYPE_VAR_STRING = 253, //!< MYSQL_TYPE_VAR_STRING
	MYSQL_TYPE_STRING = 254,     //!< MYSQL_TYPE_STRING
	MYSQL_TYPE_GEOMETRY = 255    //!< MYSQL_TYPE_GEOMETRY
};

/**
 * @brief ��װ��result_field
 */
typedef struct {
	char *name; /* Name of column */
	char *org_name;/* Original column name, if an alias */
	char *table;/* Table of column if column was a field */
	char *org_table;/* Org table name, if table was an alias */
	char *db;/* Database for table */
	char *catalog;/* Catalog for table */
	char *def; /* Default value (set by mysql_list_fields) */
	unsigned long length; /* Width of column (create length) */
	unsigned long max_length; /* Max width for selected set */
	unsigned int name_length;
	unsigned int org_name_length;
	unsigned int table_length;
	unsigned int org_table_length;
	unsigned int db_length;
	unsigned int catalog_length;
	unsigned int def_length;
	unsigned int flags; /* Div flags */
	unsigned int decimals; /* Number of decimals in field */
	unsigned int charsetnr; /* Character set */
	enum enum_field_types type; /* Type of field. See mysql_com.h for types */

} packet_result_field;

/**
 * @brief ��װ������״̬
 */
typedef struct {
	int server_status;
	int warning_count;
	guint64 affected_rows;
	guint64 insert_id;
	int status;
} query_status;


/**
 * @brief ��װ��result packet
 */
typedef struct {
    /**< �е���Ŀ */
        guint64 column_cnt;
	/**< ��������Ŀ */
	int param_cnt;
	int ret_column_cnt;
	query_status qstatus;
	/**
	 * @brief ��ǰ��ȡ�����״̬
	 */
	enum {
		STATE_READ_RESULT_BEGIN,             //!< STATE_READ_RESULT_BEGIN

		STATE_READ_RESULT_HEADER,            //!< STATE_READ_RESULT_HEADER
		STATE_READ_RESULT_FIELDS,            //!< STATE_READ_RESULT_FIELDS
		STATE_READ_RESULT_FIELDS_EOF,        //!< STATE_READ_RESULT_FIELDS_EOF
		STATE_READ_RESULT_ROWS,              //!< STATE_READ_RESULT_ROWS
		STATE_READ_RESULT_ROWS_EOF,          //!< STATE_READ_RESULT_ROWS_EOF

		STATE_READ_PREPARE_RESULT_HEADER,    //!< STATE_READ_PREPARE_RESULT_HEADER
		STATE_READ_PREPARE_RESULT_PARAMS,    //!< STATE_READ_PREPARE_RESULT_PARAMS
		STATE_READ_PREPARE_RESULT_PARAMS_EOF,//!< STATE_READ_PREPARE_RESULT_PARAMS_EOF
		STATE_READ_PREPARE_RESULT_FIELDS,    //!< STATE_READ_PREPARE_RESULT_FIELDS
		STATE_READ_PREPARE_RESULT_FIELDS_EOF //!< STATE_READ_PREPARE_RESULT_FIELDS_EOF
	} state;

	int is_already_read;

	int init_size;
	guint64 result_set_size;
} packet_result;

/**
 * @brief ������ķ�װ
 */
typedef struct {
    /**< ����� */
	guint64 command;
	/**< ���� */
	unsigned char *args;
	/**< �����ķ��䳤�� */
	int args_calloc_len;
	/**< ������ʵ�ʳ��� */
	int args_len;
	/**< ������ʼ��ʱ�� �������յ�query��ʱ��*/
	struct timeval start_time;
	/**< ������query��ʱ��*/
	struct timeval query_sent_time;
	/**< ���յ�result��ʱ��*/
	struct timeval result_read_time;
	/**< �����������ʱ�� */
	struct timeval end_time;
	/**< ��������� */
	int type;
	/**
	 * @brief �����״̬
	 */
	enum {
		QUERY_UNUSING,      //!< �����Ѿ�������ϣ��ṹ��δ��ʹ��
		QUERY_USING,        //!< �������ڴ�����
		QUERY_SERVER_RESTART//!< �������������Ӵ��������
	} status;
	/**< ��ʾ�Ƿ�Ϊ��͸���� */
	int is_designated_db;
	/**< ��͸����ָ����IP */
	char designated_db_ip[MAX_IP_LEN];
	/**< ��͸����ָ���Ķ˿� */
	int designated_port;
	/**< ��͸��������� 1Ϊָ������ 0Ϊָ��ip+�˿�*/
	int designated_type;
	/**< ��ʾ�Ƿ�Ϊ״̬��ѯ����  */
	int is_proxy_status;
	/**< ״̬��ѯ��������� 1Ϊ�û���+ip,2Ϊ���ݿ�ip+�û���+�û�ip,3Ϊproxy״̬	 */
	int status_type;


	int qtype;

	int statement_id;

	int is_last_insert_id;
} packet_query;

/**
 * @brief ��handshake���ݰ��ķ�װ
 */
typedef struct _packet_handshake {
    /**< MySQL Client/ServerЭ��İ汾�ţ�ĿǰΪ10 */
	guint protocol_version;
	/**< ��������Ϣ */
	char server_version[50];
	/**< �߳�id */
	int thread_id;
	/**< �����ַ���  */
	unsigned char scramble[21];
	/**< �ַ��� */
	unsigned char language;
} packet_handshake;


typedef struct _prepare_packet {

	packet_query query;
	int statement_id;

} prepare_packet;


/**
 * @brief �����Կͻ��˵����Ӻʹ�proxy�����ݿ�����ӽ����˷�װ
 */
struct _network_socket {
    /**< ��Ӧ��fd */
	int fd;
	/**< ���ڷ������ݵĻ����� */
	byte_array *send_buf;
	/**< send_buf��ƫ�� */
	int send_buf_offset;
	/**< ���ڽ������ݵĻ����� */
	byte_array *self_buf;
	/**< IP */
	char ip[20];
	/**< �˿� */
	int port;
	/**< �˽ṹ�屻ʹ�õĴ��� */
	int use_times;
	/**< �˽ṹ�屻��ʼʹ�õ�ʱ�� */
	struct timeval start_time;
	/**< �˽ṹ�屻�������ӳػ����ٵ�ʱ�� */
	struct timeval end_time;
	/**< ִ������Ĵ��� */
	int query_times;
	/**< ��һ��ִ��д������ʱ�� */
	struct timeval write_time;
	/**< ��¼��һ�������Ƿ�Ϊд���� */
	int is_last_query_write;

	/**< �����ͷ�� */
	unsigned char header[4];
	/**< ��ȡ��������ͷ���ĳ��� */
	int header_read_len;
	/**< ��Ϊһ��buffer������ܴ洢�˶���query�������Ҫʹ��header_offset��ָ����ǰquery��ͷ����ƫ�� */
	int header_offset;
	/**< packet id */
	size_t packet_id;
	/**< packet�ĳ��� */
	int packet_len;
	/**< �Ѿ���ȡ��packet�ĳ��� */
	int packet_read_len;
	/**< ָ��network_server�ṹ���ָ�� */
	network_server *srv;
	/**< ������Ӷ�Ӧ�����ݿ������ */
	network_database *db;
	/**< ָ��poll�ṹ���ָ�� */
	poll *poll;
	/**< ��ʾ�����Ӷ�Ӧ�����ݿ������⻹�Ǵӿ� */
	int ms;
	/**< ��ʾ�����Ӷ�Ӧ����һ�����ݿ������⻹�Ǵӿ� */
	int before_ms;
	/**< ��ʾ��ҵ��˵�proxy�����ӻ���proxy�����ݿ������ */
	int is_client_socket;
	/**< ��ʾ�Ƿ�ɸ��� */
	int is_clean;

	/**< ��ʾ���ݿ����ӱ�ʹ�õĴ��� */
	long served_client_times;
	/**< ��ʾ��ǰ�Ƿ񲿷ֶ����� */
	int is_query_send_partly;
	/**< ��ʾ�Ƿ񲿷ַ�����֤��Ϣ */
	int is_auth_send_partly;
	/**< ��ʾ�Ƿ񲿷ַ���handshake���ݰ� */
	int is_handshake_send_partly;
	/**< ��ʾ�Ƿ񲿷ַ�����֤��� */
	int is_auth_result_send_partly;
	/**< ��ʾ�Ƿ���call���� */
	int has_call_sql;
	/**< ��ʾ�Ƿ���changeuser���� */
	int has_changeuser_sql;
	/**< prepare�����ĸ��� */
	int prepare_cnt;
	/**< ��ʶ�Ƿ�ǰ�������� */
	int is_transaction;
	/**< ��ʾ�Ƿ����ڷ��ͻ�������� */
	int is_sending_cache_cmds;
	/**< ��ʶ�Ƿ���set���� */
	int has_set_sql;
	/**< ��ʶ�Ƿ���prepare���� */
	int has_prepare_sql;
	/**< ��ʶ�Ƿ���use���� */
	int has_use_sql;

/*

	*< �����������飬�Ӵӿ�Ǩ�Ƶ�����ʱ����
	GPtrArray *from_slave_to_master;
	*< ��ǰ����������±�
	int fsm_send_index;
	*< �Ƿ��Ѿ��������
	int is_fsm_send_done;

	*< �����������飬������Ǩ�Ƶ��ӿ�ʱ����
	GPtrArray *from_master_to_slave;
	*< ��ǰ����������±�
	int fms_send_index;
	*< �Ƿ��Ѿ��������
	int is_fms_send_done;
*/

	GPtrArray *cache_cmds;
	int cache_cmd_index;
//	int is_cache_send_done;


	/**
	 * @brief �����״̬
	 */
	enum {
		STATE_INIT,               //!< STATE_INIT
		STATE_CONNECTED_CLIENT,   //!< STATE_CONNECTED_CLIENT
		STATE_CONNECTED_SERVER,   //!< STATE_CONNECTED_SERVER
		STATE_READ_HANDSHAKE,     //!< STATE_READ_HANDSHAKE
		STATE_SEND_HANDSHAKE,     //!< STATE_SEND_HANDSHAKE
		STATE_READ_AUTH,          //!< STATE_READ_AUTH
		STATE_SEND_AUTH,          //!< STATE_SEND_AUTH
		STATE_READ_AUTH_RESULT,   //!< STATE_READ_AUTH_RESULT
		STATE_SEND_AUTH_RESULT,   //!< STATE_SEND_AUTH_RESULT
		STATE_READ_QUERY_RESPONSE,//!< STATE_READ_QUERY_RESPONSE
		STATE_SEND_QUERY_RESPONSE,//!< STATE_SEND_QUERY_RESPONSE
		STATE_READ_QUERY,         //!< STATE_READ_QUERY
		STATE_SEND_QUERY,         //!< STATE_SEND_QUERY

		STATE_READ_QUERY_RESULT,  //!< STATE_READ_QUERY_RESULT
		STATE_SEND_QUERY_RESULT,  //!< STATE_SEND_QUERY_RESULT

		STATE_WAIT_CLOSE,         //!< STATE_WAIT_CLOSE
		STATE_ERROR               //!< STATE_ERROR
	} state;
	/**< ��һ�α�ʹ�õ�ʱ�� */
	time_t last_active_time;
	/**< handshake ���ݰ� */
	packet_handshake handshake;
	/**< result���ݰ� */
	packet_result result;
	/**< ��Ӧ��ҵ����û��� */
	product_user *p_user;
	/**< ��ǰ��������� */
	packet_query query;
	/**< ��ʾ�Ƿ���������ӿ�֮���Ǩ�� */
	int is_exec_last_use_query;
	/**< ��Ӧ��ҵ������� */
	network_socket *client;
	/**< ��Ӧ�����ݿ����� */
	network_socket *server;
	/**< ��ǰʹ�õ����ݿ����� */
	char current_db[MAX_DEFAULT_DB_NAME_LEN];
	/**< ��Ӧ���û�����ip������״̬��ѯ���� */
	char username_and_ip[MAX_STATUS_TYPE_1_KEY];
	/**< ͨ���û�����ip��ϣ������ֵ */
	guint key_type1;
	/**< ��Ӧ�����ݿ�ip+�û���+�û�ip������״̬��ѯ���� */
	char dbip_and_user_and_userip[MAX_STATUS_TYPE_2_KEY];
	/**< ͨ�����ݿ�ip+�û���+�û�ip��ϣ������ֵ */
	guint key_type2;
	/**< ��ʾ�Ƿ��Ѿ�������֤ */
	int is_authed;
	/**< ��ʾ�ͻ��������Ƿ��Ѿ������������ݿ����� */
	int is_using_db;
	/**< ��ʾ�Ƿ��Ѿ���֤����IP */
	int is_check_ip;
	/**< sockaddr�ṹ�� */
	struct sockaddr_in addr;
	/**< ��ʾ���ݿ������Ƿ������ӳ��� */
	int is_in_pool;
	/**< ��ʾ��ǰ���͵Ļ������������� */
	guint64 cache_cmd;
	/**< ��ʾ��ǰ�����Ƿ��ڴ�͸״̬�� */
	int is_designated;
	guint session_key;

    int is_auth_failed;

    GArray* prepare_write_array;
    GArray* prepare_read_array;

//    GHashTable* prepare_statement_ids;

	GPtrArray* prepare_statement_ids;
    
    int statement_id;

	int query_processed_num;

	unsigned long long last_insert_id;
    GArray* last_insert_id_array;
	
	int is_execute_last_insert_id;

	/* CLIENT handshake & auth option */
	unsigned char client_found_rows;
	unsigned char client_ignore_space;
	/* Client is executing load data cmd*/
	int loading_data;
	/* Server  executed a sql that the MySQL had a out of memory*/
	int is_during_err;
};

/**
 * @brief ������װһ�������ӿ�Ļ�����Ϣ
 */
struct _db_group_info{
    /**< �洢������Ϣ�Ľṹ�� */
    network_database *basic_db;
    /**< ��ʾ�����⻹�Ǵӿ� */
    int is_slave;
    /**< �������е��±� */
    int array_index;

    time_t modify_time;
};
typedef struct _db_group_info db_group_info;

/**
 * @brief ���ο������Ӻ����Ķ���
 */
typedef int (*hook_func)(network_socket **s, int client_fd);

/**
 * @brief ���ο�����������ṹ
 */
typedef struct _hook_array {
    /**< so���������� */
    char* so_names[MAX_HOOK_SO];
    /**< ���ص�so������� */
    int so_nums;
    /**< ���Ӻ������� */
    hook_func* funcs[MAX_HOOK_SO];
} hook_array;

/**
 * @brief ��װ����������Ϣ��ص����ݵĽṹ��
 */
typedef struct {
    /**< zookeeper��� */
	zhandle_t *zh;

	//key Ϊzk path��valueΪdb_group_info
	GHashTable *basic_db_info;

	GPtrArray *zk_path_array;

	char zk_host[MAX_ZOOKEEPER_PATH_LEN];

	char zk_conf_dir[ZK_CONF_DIR_LEN];

	char zk_log[ZK_LOG_FILE];

	int is_zk_enable;

	int port;
	int max_threads;
	int backlog;
	int reconnect_times;
	char log_dir[MAX_LOG_DIR_LEN];
	char log_filename[MAX_LOGFILE_NAME_LEN];
	int log_maxsize;

	time_t timeout_check_interval;
	time_t client_timeout;
	time_t server_timeout;

	//XXX д�������ʱ��
	unsigned long int write_time_interval;

	long conn_pool_socket_max_serve_client_times;

	int log_query_min_time;
	int log_level;

	//keyΪusername,valueΪproduct_user
	GHashTable *users;

	GHashTable *clusters;

	GHashTable *db_user;

//	GHashTable *product_lines;

	GPtrArray *auth_ips;

	//XXX ���������������״̬��ѯ���
	int max_product_user_num;

	int max_product_ip_num;

	int max_db_ip_num;

	//XXX ÿ���и������õĲ���������ֶε�ֵ������0��1֮��仯����ʼֵΪ0,product_user��db_user�Լ�network_database�е�is_old�ֶγ�ʼֵҲΪ0,ÿ�θ�������ʱ���µ����õ�is_old�ֶ�
	//��Ϊ�仯���is_updated
//	int update_flag;

	int user_update_flag;

	//XXX ��ʾ�Ƿ����������
	//	int is_updating;

	time_t server_timeout_short;

//	GArray *pid_array;

	char conf_path[MAX_FILE_NAME_LEN];

	hook_array *h_array;

	char pid[10];

	GHashTable *sessions;

	int mmap_flag;

	int proxy_status_interval;

	time_t conf_modify_time;

	int is_autoload_enable;

	int zk_timeout;

	int zk_interval;

	int max_query_size;
	int max_query_num;

} network_server_config;

struct _conn_pool;
typedef struct _conn_pool conn_pool;

typedef struct _network_socket_pool {
	GQueue *sockets;
	network_server *srv;
} network_socket_pool;




struct _network_server {

	network_server_config *config;
	network_socket *listen_socket;

	struct timeval cur_time;

	poll *poll;
	network_socket_pool *sockets_pool;

	status_user_and_ip *s1;
	status_user_and_ip *child_s1;
	int s1_num;

	status_dbip_and_user *s2;
	status_dbip_and_user *child_s2;
	int s2_num;

	status_mysql_proxy_layer *s3;
	status_mysql_proxy_layer *child_s3;
	int s3_num;

	status_mmap_flag *s4;
	status_mmap_flag *child_s4;
	int s4_num;


};


#define call_hook_func(i1,i2,p1,p2)    ((*(srv->config->h_array->funcs[i1])[i2])(p1,p2))

extern hook_array* hook_array_create();

void hook_array_free(hook_array* array);

int load_hook_so(char* path, hook_array* array);


extern db_user* db_user_create();
extern void db_user_free();

extern network_socket* network_socket_create();
extern network_socket* create_connect_network_socket(network_database *db);
extern network_socket* create_listen_network_socket();
extern int setnonblock(int fd);

extern size_t packet_header_get_len(char *header);

//extern network_connection* network_connection_create();
//extern void network_connection_free(network_connection *con);

//extern network_queue* network_queue_create();

extern int set_header(unsigned char *header, size_t len,
		unsigned char packet_id);
extern int handshake_send(network_socket *s);
extern int ok_send(network_socket *s);
extern int query_read(network_socket *s, network_server *srv);

extern int real_write_chunks(network_socket *s, size_t len);
extern int real_read_chunks(network_socket *s);

int conn_pool_add(network_socket *s);
//int conn_pool_remove(conn_pool *p, conn_pool_entry *entry);
//network_socket* conn_pool_get(conn_pool *p, db_user *user, int ms);
network_socket* conn_pool_get(network_socket *client);
conn_pool* conn_pool_create();
void conn_pool_free(conn_pool *p);

extern network_server_config* get_network_server_config();

extern network_database* network_database_create();
extern void network_database_free(network_database *db);

packet_query* packet_read_query(network_socket *s);
extern void packet_query_free(packet_query *query);

packet_handshake* packet_read_handshake(network_socket *s);

inline int protocol_get_string(unsigned char *data, int size, guint *off,
		char *ret_str, int capacity);
inline gchar* protocol_get_string_len(byte_array *packet, guint *off, int len);

extern network_socket* network_socket_get_db_socket(network_server *srv,
		network_socket *client, poll *poll);
extern unsigned char packet_read_result_header(network_socket *s);
extern void client_free(network_socket *s, int p_server);

#define protocol_decode_len(data, off, ret_len) \
	do { \
		guint64 ret = 0; \
		unsigned char *bytestream = (unsigned char *)data; \
		if( bytestream[off] < 251){ \
			ret = bytestream[off]; \
		} else if(bytestream[off] == 251){ \
			ret = 0; \
		} else if(bytestream[off] == 252){ \
			ret = (bytestream[off + 1] << 0 ) | (bytestream[off + 2] << 8); \
			off += 2; \
		} else if(bytestream[off] == 253){ \
			ret = (bytestream[off + 1] << 0 ) | (bytestream[off + 2] << 8) \
			| (bytestream[off + 3] << 16); \
			off += 4; \
		} else if(bytestream[off] == 254){ \
			ret = -1; \
		} \
		off += 1; \
		ret_len = ret; \
	} while(0)

extern int connect_db_error_send(network_socket *s);
extern int conn_pool_delete(network_socket *s);
//inline int is_need_response(packet_query *query);
inline int is_need_response(network_socket *client);
extern void server_free(network_socket *s, int p_client);
extern network_socket_pool* network_socket_pool_create();
extern network_socket* network_socket_get(network_socket_pool *pool,
		int is_server);

extern int init_zookeeper(network_server_config *config, char *zk_host,
        char *zk_log_file,int is_watch);
#endif
