#ifndef __CONFIG_H_
#define __CONFIG_H_

#define CONFIG_CLUSTER_GROUP "Cluster"
#define CONFIG_CLUSTER_NAME "cluster_name"

#define CONFIG_DBUSER_GROUP_PREFIX "DB_User"
#define CONFIG_DBUSER_CLUSTER_NAME "cluster_name"
#define CONFIG_DBUSER_NAME "db_username"
#define CONFIG_DBUSER_PASSWORD "db_password"
#define CONFIG_DBUSER_DEFAULT_DB "default_db"
#define CONFIG_DBUSER_DEFAULT_CHARSET "default_charset"
#define CONFIG_DBUSER_DEFAULT_MASTER_CONNECTION_NUM "default_master_connection_num"
#define CONFIG_DBUSER_DEFAULT_SLAVE_CONNECTION_NUM "default_slave_connection_num"

#define CONFIG_DB_MASTER_GROUP_PREFIX "Master_Host"
#define CONFIG_DB_SLAVE_GROUP_PREFIX "Slave_Host"
#define CONFIG_DB_CLUSTER_NAME "cluster_name"
#define CONFIG_DB_HOST "host"
#define CONFIG_DB_PORT "port"
#define CONFIG_DB_MAX_CONNECTIONS "max_connections"
#define CONFIG_DB_MIN_CONNECTIONS "min_connections"
#define CONFIG_DB_CONNECT_TIMEOUT "connect_timeout"
#define CONFIG_DB_CONNECT_TIMEOUT_DEFAULT 1000
#define CONFIG_DB_TIME_RECONNECT_INTERVAL "time_reconnect_interval"
#define CONFIG_DB_TIME_RECONNECT_INTERVAL_DEFAULT 30
#define CONFIG_DB_WEIGHT "weight"
#define CONFIG_DB_HOST_NAME "name"
#define CONFIG_DB_RESERVED_MASTER_CONNECTIONS "reserved_master_connections"

#define CONFIG_MPL_GROUP "MySQL_Proxy_Layer"
#define CONFIG_MPL_PORT "port"
#define CONFIG_MPL_ZK_HOST "zk_host"
#define CONFIG_MPL_ZK_CONF_DIR "zk_conf_dir"
#define CONFIG_MPL_ZK_LOG "zk_log"
#define CONFIG_MPL_ZK_ENABLE "zk_enable"
#define CONFIG_MPL_MAX_THREADS "max_threads"
#define CONFIG_MPL_BACKLOG "backlog"
#define CONFIG_MPL_RECONNECT_TIMES "reconnect_times"
#define CONFIG_MPL_RECONNECT_TIMES_DEFAULT 3
#define CONFIG_MPL_MAX_THREAD_CLIENTS "max_thread_clients"
#define CONFIG_MPL_LOG_DIR "log_dir"
#define CONFIG_MPL_LOG_FILENAME "log_filename"
#define CONFIG_MPL_LOG_MAXSIZE "log_maxsize"
#define CONFIG_MPL_TIMEOUT_CHECK_INTERVAL "timeout_check_interval"
#define CONFIG_MPL_CLIENT_TIMEOUT "client_timeout"
#define CONFIG_MPL_SERVER_TIMEOUT "server_timeout"
#define CONFIG_MPL_SERVER_TIMEOUT_SHORT "server_timeout_short"
#define CONFIG_MPL_LOG_QUERY_MIN_TIME "log_query_min_time"
#define CONFIG_MPL_LOG_LEVEL "log_level"
#define CONFIG_MPL_CONN_POOL_SOCKET_MAX_SERVE_CLIENT_TIMES "conn_pool_socket_max_serve_client_times"
#define CONFIG_MPL_WRITE_TIME_INTERVAL "write_time_interval"
#define CONFIG_MPL_SO_PATH_PREFIX "so_path"
#define CONFIG_MPL_PROXY_STATUS_INTERVAL "proxy_status_interval"
#define CONFIG_MPL_AUTOLOAD_LOCAL_CONF_ENABLE "autoload_local_conf_enable"
#define CONFIG_MPL_ZK_TIMEOUT "zk_timeout"
#define CONFIG_MPL_ZK_INTERVAL "zk_interval"
#define CONFIG_MPL_MAX_QUERY_SIZE "max_query_size"
#define CONFIG_MPL_MAX_QUERY_NUM "max_query_num"

#define CONFIG_PRODUCTUSER_GROUP_PREFIX "Product_User"
#define CONFIG_PRODUCTUSER_LINE_NAME "product_line_name"
#define CONFIG_PRODUCTUSER_USERNAME "username"
#define CONFIG_PRODUCTUSER_PASSWORD "password"
#define CONFIG_PRODUCTUSER_DB_USERNAME "db_username"
#define CONFIG_PRODUCTUSER_MAX_CONNECTIONS "max_connections"
#define CONFIG_PRODUCTUSER_AUTH_IP_PREFIX "authip"

#define CONFIG_AUTH_IP_GROUP_PREFIX "Auth_IP"
#define CONFIG_AUTH_IP_IP "ip"

#define CONFIG_MPL_EPOLL_MAX_SIZE 60000

//#define CONFIG_STATUS_MAX_PRODUCTLINE_NUM 10
#define CONFIG_STATUS_MAX_PRODUCTUSER_NUM 50
#define CONFIG_STATUS_MAX_IP_NUM 50
#define CONFIG_STATUS_MAX_DB_NUM 50

#define MAX_STATUS_TYPE_1_KEY 100
#define MAX_STATUS_TYPE_2_KEY 100
#define MAX_STATUS_IPS_LEN 120
#define MAX_STATUS_TIME_LEN 30

#define MAX_MASTER_IPS 50
#define MAX_SLAVE_IPS 50

#endif
