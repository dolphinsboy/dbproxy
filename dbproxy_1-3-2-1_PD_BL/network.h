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
 * @brief 连接池中用来存放数据库连接的队列
 */
typedef struct {
    /**< 主库队列*/
	GQueue *w_queue;
	/**< 从库队列*/
	GQueue *r_queue;
} conn_pool_queue;

/**
 * @brief 对网络地址的封装
 */
typedef struct {
    /**< sockaddr_in结构的地址*/
	struct sockaddr_in addr_ip;
	/**< ip地址字符串*/
	char addr_name[MAX_IP_LEN];
	/**< 地址长度*/
	int addr_len;
	/**< 端口*/
	int port;
} network_address;

/**
 * @brief 验证IP
 */
typedef struct {
    /**< IP地址*/
	struct in_addr addr;
} auth_ip;

/**
 * @brief 集群信息
 */
struct _cluster {
    /**< 集群的名字 */
	char cluster_name[MAX_CLUSTER_NAME_LEN];
	/**< 此集群中的主库 */
	GPtrArray *master_dbs;
	/**< 此集群中的从库 */
	GPtrArray *slave_dbs;
	/**< 连接池
	 * 此处是一个哈希表，key为数据库用户名，value为另一个哈希表，其key为数据库的名字，value为指向conn_pool_queue结构体的指针
	 */
	GHashTable *db_conn_pools;
	/**<
	 * 主库更新标示,当有更新主库时，此字段加1
	 */
	int w_update_flag;
	/**<
	 * 从库更新标示,当有更新主库时，此字段加1
	 */
	int r_update_flag;
};
typedef struct _cluster cluster;


/**
 * @brief 数据库用户名
 */
typedef struct _db_user {
    /**< 用户名 */
	char username[MAX_USERNAME_LEN];
	/**< 密码 */
	char password[MAX_PASSWORD_LEN];
	/**< 加密字符串 */
	unsigned char scramble_password[21];
	/**< 加密字符串的长度 */
	int scramble_len;
	/**< 此用户名所属的主从集群 */
	cluster *clus;
	/**< 默认数据库 */
	char default_db[MAX_DEFAULT_DB_NAME_LEN];
	/**< 默认字符集 */
	unsigned char default_charset;
	/**< 当前使用此用户名的客户端连接数 */
	int current_connections;
	/**< 标示此用户名是否是旧用户名 */
	int is_old;
} db_user;

/**
 * @brief 对数据库服务器的封装
 */
struct _network_database {
    /**< 此数据库服务器所从属的集群 */
	cluster *clus;
	/**< 此数据库服务器的名字 */
	char host_name[MAX_HOST_NAME_LEN];
	/**< 对应的network_address结构体，封装了地址、端口等信息 */
	network_address addr;
	/**< 此数据库服务器允许连接的最大连接数 */
	guint max_connections;
	/**< 此数据库服务器允许连接的最小连接数 */
	guint min_connections;
	/**< 当此数据库服务器作为master时，如果当前连接数小于此保留数，则不允许其它slave连接占用本master的连接 */
	guint reserved_master_connections;
	/**< 配置文件中所属的GROUP */
	char group_name[MAX_GROUP_LEN];
	/**< 连接时的超时时间 */
	int connect_timeout;
	/**< 失败重连的时间间隔 */
	int time_reconnect_interval;
	/**< 上一次失效的时间 */
	time_t last_fail_time;
	/**< 当前连接数 */
	int cur_connected;
	/**< 标示是主库还是从库 */
	int ms;
	/**< 权重 */
	int weight;
	/**< 标示是否为旧的数据库服务器 */
	int is_old;
	/**< 其所对应的zookeeper路径*/
	char zk_path[MAX_ZOOKEEPER_PATH_LEN];
	/**< 此数据库的IP哈希的结果，用于状态查询 */
	guint key;
};
typedef struct _network_database network_database;

/**
 * @brief 对产品线用户的封装
 */
struct _product_user {
	/**< 用户名 */
	char username[MAX_USERNAME_LEN];
	/**< 密码 */
	char password[MAX_PASSWORD_LEN];
	/**< 加密字符串 */
	unsigned char scramble_password[21];
	/**< 加密字符串的长度 */
	int scramble_len;
	/**< 与此产品线用户名对应的数据库用户名 */
	db_user *d_user;
	/**< 当前产品线用户名所能使用的最大数据库连接数 */
	int max_connections;
	/**< 当前使用此用户名登录到proxy的客户端数目 */
	int current_connections;
	/**< 标示此用户名是否是旧的 */
	int is_old;
	/**< 与此用户名相关的局部授权IP */
	GPtrArray *auth_ips;
};
typedef struct _product_user product_user;

/**
 * @brief 用于状态查询，封装了数据库的IP和对应的连接数
 */
struct _db_ip_key{
    /**< 连接数 */
	int use_num;
	/**< 与network_database结构体中的key字段对应，用于标示数据库 */
	guint key;
	/**< 数据库的IP */
	char db_ip[MAX_IP_LEN];
};
typedef struct _db_ip_key db_ip_key;

/**
 * @brief 封装了与用户名+ip相关的状态查询内容
 */
struct _status_user_and_ip {
    /**< 用于标示共享内存中的内存块是否有被使用 */
	int is_used;
	/**< 用于定位的key */
	guint key;
	/**< 用户名+ip */
	char username_and_ip[MAX_STATUS_TYPE_1_KEY];
	/**< 到proxy的连接数 */
	int proxy_connections;
	/**< 到数据库的连接数 */
	int db_connections;
	/**< 对应的主库信息 */
//	db_ip_key master_ips[MAX_MASTER_IPS];
	/**< 对应的从库信息 */
//	db_ip_key slave_ips[MAX_SLAVE_IPS];
	/**< 进程号 */
	char pid[10];


	char masters[MAX_STATUS_IPS_LEN];

	char slaves[MAX_STATUS_IPS_LEN];

	char cur_time[MAX_STATUS_TIME_LEN];

};
typedef struct _status_user_and_ip status_user_and_ip;

/**
 * @brief 封装了与数据库IP和用户名相关的状态查询内容
 */
struct _status_dbip_and_user {
    /**< 用于标示共享内存中的内存块是否有被使用 */
	int is_used;
	/**< 用于定位的key */
	guint key;
	/**< 数据库IP+用户名+用户IP */
	char dbip_and_user_and_userip[MAX_STATUS_TYPE_2_KEY];
	/**< 连接数 */
	int connection_num;
	/**< 进程号 */
	char pid[10];
	char cur_time[MAX_STATUS_TIME_LEN];
};
typedef struct _status_dbip_and_user status_dbip_and_user;

/**
 * @brief 封装了与MySQL Proxy Layer本身相关的状态查询内容
 */
struct _status_mysql_proxy_layer {
    /**< 当前子进程所使用的内存量 */
    char vmsize[MAX_PROC_STATUS_LEN];
    /**< 每一个连接池中的连接数 */
    char conn_pool_stat[MAX_DB_USER_NUM*MAX_DB_NUM*MAX_PROC_CONN_LEN*2];
    /**< network_socket连接池中的连接数 */
	int network_socket_pool_num;
	/**< 时间戳 */
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
 * @brief 对MySQL数据类型的定义
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
 * @brief 封装了result_field
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
 * @brief 封装了请求状态
 */
typedef struct {
	int server_status;
	int warning_count;
	guint64 affected_rows;
	guint64 insert_id;
	int status;
} query_status;


/**
 * @brief 封装了result packet
 */
typedef struct {
    /**< 列的数目 */
        guint64 column_cnt;
	/**< 参数的数目 */
	int param_cnt;
	int ret_column_cnt;
	query_status qstatus;
	/**
	 * @brief 当前读取结果的状态
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
 * @brief 对请求的封装
 */
typedef struct {
    /**< 命令号 */
	guint64 command;
	/**< 参数 */
	unsigned char *args;
	/**< 参数的分配长度 */
	int args_calloc_len;
	/**< 参数的实际长度 */
	int args_len;
	/**< 此请求开始的时间 ，即接收到query的时间*/
	struct timeval start_time;
	/**< 发送完query的时间*/
	struct timeval query_sent_time;
	/**< 接收到result的时间*/
	struct timeval result_read_time;
	/**< 此请求结束的时间 */
	struct timeval end_time;
	/**< 请求的类型 */
	int type;
	/**
	 * @brief 请求的状态
	 */
	enum {
		QUERY_UNUSING,      //!< 请求已经处理完毕，结构体未被使用
		QUERY_USING,        //!< 请求正在处理中
		QUERY_SERVER_RESTART//!< 正处于冗余连接处理过程中
	} status;
	/**< 标示是否为穿透命令 */
	int is_designated_db;
	/**< 穿透命令指定的IP */
	char designated_db_ip[MAX_IP_LEN];
	/**< 穿透命令指定的端口 */
	int designated_port;
	/**< 穿透命令的类型 1为指定主库 0为指定ip+端口*/
	int designated_type;
	/**< 标示是否为状态查询命令  */
	int is_proxy_status;
	/**< 状态查询命令的类型 1为用户名+ip,2为数据库ip+用户名+用户ip,3为proxy状态	 */
	int status_type;


	int qtype;

	int statement_id;

	int is_last_insert_id;
} packet_query;

/**
 * @brief 对handshake数据包的封装
 */
typedef struct _packet_handshake {
    /**< MySQL Client/Server协议的版本号，目前为10 */
	guint protocol_version;
	/**< 服务器信息 */
	char server_version[50];
	/**< 线程id */
	int thread_id;
	/**< 加密字符串  */
	unsigned char scramble[21];
	/**< 字符集 */
	unsigned char language;
} packet_handshake;


typedef struct _prepare_packet {

	packet_query query;
	int statement_id;

} prepare_packet;


/**
 * @brief 对来自客户端的连接和从proxy到数据库的连接进行了封装
 */
struct _network_socket {
    /**< 对应的fd */
	int fd;
	/**< 用于发送数据的缓冲区 */
	byte_array *send_buf;
	/**< send_buf的偏移 */
	int send_buf_offset;
	/**< 用于接收数据的缓冲区 */
	byte_array *self_buf;
	/**< IP */
	char ip[20];
	/**< 端口 */
	int port;
	/**< 此结构体被使用的次数 */
	int use_times;
	/**< 此结构体被开始使用的时间 */
	struct timeval start_time;
	/**< 此结构体被放入连接池或销毁的时间 */
	struct timeval end_time;
	/**< 执行请求的次数 */
	int query_times;
	/**< 上一次执行写操作的时间 */
	struct timeval write_time;
	/**< 记录上一个请求是否为写操作 */
	int is_last_query_write;

	/**< 请求的头部 */
	unsigned char header[4];
	/**< 读取到的请求头部的长度 */
	int header_read_len;
	/**< 因为一个buffer里面可能存储了多条query，因此需要使用header_offset来指定当前query的头部的偏移 */
	int header_offset;
	/**< packet id */
	size_t packet_id;
	/**< packet的长度 */
	int packet_len;
	/**< 已经读取的packet的长度 */
	int packet_read_len;
	/**< 指向network_server结构体的指针 */
	network_server *srv;
	/**< 与此连接对应的数据库服务器 */
	network_database *db;
	/**< 指向poll结构体的指针 */
	poll *poll;
	/**< 标示此连接对应的数据库是主库还是从库 */
	int ms;
	/**< 标示此连接对应的上一个数据库是主库还是从库 */
	int before_ms;
	/**< 标示是业务端到proxy的连接还是proxy到数据库的连接 */
	int is_client_socket;
	/**< 标示是否可复用 */
	int is_clean;

	/**< 标示数据库连接被使用的次数 */
	long served_client_times;
	/**< 标示当前是否部分读请求 */
	int is_query_send_partly;
	/**< 标示是否部分发送验证信息 */
	int is_auth_send_partly;
	/**< 标示是否部分发送handshake数据包 */
	int is_handshake_send_partly;
	/**< 标示是否部分发送验证结果 */
	int is_auth_result_send_partly;
	/**< 标示是否有call命令 */
	int has_call_sql;
	/**< 标示是否有changeuser命令 */
	int has_changeuser_sql;
	/**< prepare参数的个数 */
	int prepare_cnt;
	/**< 标识是否当前在事务中 */
	int is_transaction;
	/**< 标示是否正在发送缓存的命令 */
	int is_sending_cache_cmds;
	/**< 标识是否有set命令 */
	int has_set_sql;
	/**< 标识是否有prepare命令 */
	int has_prepare_sql;
	/**< 标识是否有use命令 */
	int has_use_sql;

/*

	*< 缓存命令数组，从从库迁移到主库时发送
	GPtrArray *from_slave_to_master;
	*< 当前发送命令的下标
	int fsm_send_index;
	*< 是否已经发送完毕
	int is_fsm_send_done;

	*< 缓存命令数组，从主库迁移到从库时发送
	GPtrArray *from_master_to_slave;
	*< 当前发送命令的下标
	int fms_send_index;
	*< 是否已经发送完毕
	int is_fms_send_done;
*/

	GPtrArray *cache_cmds;
	int cache_cmd_index;
//	int is_cache_send_done;


	/**
	 * @brief 命令处理状态
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
	/**< 上一次被使用的时间 */
	time_t last_active_time;
	/**< handshake 数据包 */
	packet_handshake handshake;
	/**< result数据包 */
	packet_result result;
	/**< 对应的业务端用户名 */
	product_user *p_user;
	/**< 当前处理的请求 */
	packet_query query;
	/**< 标示是否进行了主从库之间的迁移 */
	int is_exec_last_use_query;
	/**< 对应的业务端连接 */
	network_socket *client;
	/**< 对应的数据库连接 */
	network_socket *server;
	/**< 当前使用的数据库名字 */
	char current_db[MAX_DEFAULT_DB_NAME_LEN];
	/**< 对应的用户名和ip，用于状态查询命令 */
	char username_and_ip[MAX_STATUS_TYPE_1_KEY];
	/**< 通过用户名和ip哈希出来的值 */
	guint key_type1;
	/**< 对应的数据库ip+用户名+用户ip，用于状态查询命令 */
	char dbip_and_user_and_userip[MAX_STATUS_TYPE_2_KEY];
	/**< 通过数据库ip+用户名+用户ip哈希出来的值 */
	guint key_type2;
	/**< 标示是否已经经过验证 */
	int is_authed;
	/**< 标示客户端连接是否已经被分配了数据库连接 */
	int is_using_db;
	/**< 标示是否已经验证过了IP */
	int is_check_ip;
	/**< sockaddr结构体 */
	struct sockaddr_in addr;
	/**< 标示数据库连接是否在连接池中 */
	int is_in_pool;
	/**< 标示当前发送的缓存命令的命令号 */
	guint64 cache_cmd;
	/**< 标示当前连接是否处于穿透状态中 */
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
 * @brief 用来封装一批主库或从库的基本信息
 */
struct _db_group_info{
    /**< 存储基本信息的结构体 */
    network_database *basic_db;
    /**< 标示是主库还是从库 */
    int is_slave;
    /**< 在数组中的下标 */
    int array_index;

    time_t modify_time;
};
typedef struct _db_group_info db_group_info;

/**
 * @brief 二次开发钩子函数的定义
 */
typedef int (*hook_func)(network_socket **s, int client_fd);

/**
 * @brief 二次开发钩子数组结构
 */
typedef struct _hook_array {
    /**< so库名字数组 */
    char* so_names[MAX_HOOK_SO];
    /**< 加载的so库的数量 */
    int so_nums;
    /**< 钩子函数数组 */
    hook_func* funcs[MAX_HOOK_SO];
} hook_array;

/**
 * @brief 封装了与配置信息相关的数据的结构体
 */
typedef struct {
    /**< zookeeper句柄 */
	zhandle_t *zh;

	//key 为zk path，value为db_group_info
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

	//XXX 写操作间隔时间
	unsigned long int write_time_interval;

	long conn_pool_socket_max_serve_client_times;

	int log_query_min_time;
	int log_level;

	//key为username,value为product_user
	GHashTable *users;

	GHashTable *clusters;

	GHashTable *db_user;

//	GHashTable *product_lines;

	GPtrArray *auth_ips;

	//XXX 下面三个配置项都与状态查询相关
	int max_product_user_num;

	int max_product_ip_num;

	int max_db_ip_num;

	//XXX 每次有更新配置的操作，这个字段的值都会在0与1之间变化，初始值为0,product_user、db_user以及network_database中的is_old字段初始值也为0,每次更新配置时，新的配置的is_old字段
	//置为变化后的is_updated
//	int update_flag;

	int user_update_flag;

	//XXX 标示是否更新配置中
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
