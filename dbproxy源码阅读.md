###1、参数读取
+ 通getopt函数
+ VERSION 通过gcc -DVERSION参数指定
+ BuildDate 通过宏定义__DATE__以及__TIME__指定

###2、创建net对应的server

```c
network_server *srv;
srv = create_network_server(config_file)
```

####2.1 返回值类型

```c
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
```
####2.2 MySQL相关配置信息

```c

typedef struct {
	int port;
	    GHashTable *users;

    GHashTable *clusters;

    GHashTable *db_user;

//  GHashTable *product_lines;

    GPtrArray *auth_ips;
    .....
}network_server_config
```

####2.3 get\_network\_server_config配置文件解析
#####2.3.1 get\_default\_network\_server_config
进行配置文件相关参数的初始化工作。

```c
config->users   hash_table
config->auth_ips hash_table
config->db_user hash_table
config->clusters  hash_table
config->basic_db_info hash_table
config->zk_path_array  ptr_array
config->sessions g_hash_table_new

config->h_array = hook_array_create()

//其他一些全局参数
```

#####2.3.2 从文件中读取相关配置信息

```c
GKeyFile *conf_file;

conf_file = g_key_file_new()
g_key_file_load_from_file(conf_file, conf_path, 0, NULL)

groups = g_key_file_get_groups(conf_file, &g_cnt))

```
**config的解析demo**
[https://github.com/dolphinsboy/code_for_c/blob/master/glib/get_config_file.c](https://github.com/dolphinsboy/code_for_c/blob/master/glib/get_config_file.c)

```c
通过strstr把group进行对应
strstr(groups[i], CONFIG_MPL_GROUP)
```
通过函数strstr将下面两个group(Slave_Host_1和Slave_Host_2)对应起来:

```bash
[Slave_Host_1]
#name                   = tc-dba-cc00.tc 
cluster_name            = DBA_C_demo
host                    = 10.1.1.1

[Slave_Host_2]
#name                   = tc-dba-cc00.tc 
cluster_name            = DBA_C_demo
host                    = 10.1.1.1

```

**init_mysql\_proxy\_layer**

解析这个部分

```c
[MySQL_Proxy_Layer]
port                  = 4051

zk_enable             = 0
zk_host               = st.zk.dba.baidu.com:8181
zk_conf_dir           = ./conf/
zk_log                = ./log/zookeeper.log
zk_timeout            = 30000
zk_interval           = 60

max_threads           = 2
backlog               = 50
log_dir               = ./log/
log_filename          = dbproxy.log
log_maxsize           = 1800
```

 主要包含两类参数解析int以及string：
 
```c
strncasecmp(CONFIG_MPL_PORT, keys[j], strlen(CONFIG_MPL_PORT))
config->port = strtoul(value, NULL, 10);

(0 == strncasecmp(CONFIG_MPL_ZK_HOST, keys[j], strlen(CONFIG_MPL_ZK_HOST)))
snprintf(config->zk_host, sizeof(config->zk_host),"%s", value);
```

通过判断key的名字与参数名字相同之后，将其在config结构体中变量进行赋值。

**init_zookeeper**
使用zookeeper的C API进行操作。
[http://www.cnblogs.com/haippy/archive/2013/02/24/2924567.html](http://www.cnblogs.com/haippy/archive/2013/02/24/2924567.html)

<font color='red'>dbproxy没有使用zookeeper，这里先记下，后续再研究这块。</font>


**init_cluster**

```c
//根据group名称进行cluster的解析中

strstr(groups[i], CONFIG_CLUSTER_GROUP)
```

dbproxy分多个cluster，需要对这些cluster的参数进行解析。

**cluster结构体**：

```c
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
    ¦* 此处是一个哈希表，key为数据库用户名，value为另一个哈希表，其key为数据库的名字，value为指向conn_pool_queue结构体的指针
    ¦*/
    GHashTable *db_conn_pools;
    /**<
    ¦* 主库更新标示,当有更新主库时，此字段加1
    ¦*/
    int w_update_flag;                                                                                                                                                           
    /**<
    ¦* 从库更新标示,当有更新主库时，此字段加1
    ¦*/
    int r_update_flag;
};
typedef struct _cluster cluster;
```

**cluster初始化**

```c
cluster *clus;
clus = (cluster*) cluster_create()

//cluster_create实现方式
cluster *c = (cluster*) calloc(1, sizeof(cluster));
c->master_dbs = g_ptr_array_new()
c->slave_dbs = g_ptr_array_new()
c->db_conn_pools = g_hash_table_new(g_str_hash, g_str_equal)

//主要对一些数组以及hashtable创建新的对象
```

**解析配置文件中的多个cluster**

支持多个cluster:

```c
clus = (cluster*) cluster_create())
strncpy(clus->cluster_name, value,MAX_CLUSTER_NAME_LEN)
g_hash_table_insert(config->clusters, clus->cluster_name, clus);

```

**解析配置文件中的Master_Host**

```c
strstr(groups[i], CONFIG_DB_MASTER_GROUP_PREFIX)

int init_network_database_by_group(network_server_config *config,
     GKeyFile *conf_file, gchar *group, int is_slave,
     int is_read_from_local, int is_update)
```
通过参数is\_read\_from_local来判断是否从zookeeper中读取。

对应的配置文件：

```bash
[Master_Host_1]
#name                   = tc-dba-cc00.tc 
cluster_name            = DBA_C_demo
host                    = 10.1.1.1
port                    = 3306
max_connections         = 100 
connect_timeout         = 200000
time_reconnect_interval = 30
reserved_master_connections=100
weight                  = 1 

```
上面的配置信息对应的结构体如下:

```c
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
```

**init\_network\_database\_by\_group的实现过程**

+ 初始化
	
	```c
	network_database_create
	db = calloc(1, sizeof(network_database)))
	```
+  解析配置文件，对network_database *db进行初始化
	+ IP和 Host单独封装在一个结构体中
	
	```c
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
	```
	这里面有个套接字结构
	
	```c
	struct sockaddr_in addr_ip;
	
	db->addr.addr_ip.sin_port = htons(db->addr.port);
	db->addr.addr_len = sizeof(db->addr.addr_ip);
	db->addr.addr_ip.sin_family = AF_INET;
	inet_aton(value, &(db->addr.addr_ip.sin_addr))
	```
	
+  解析配置文件，对network_database *db进行初始化

	```c
		db->key = str_hash(db->addr.addr_name)
	```
