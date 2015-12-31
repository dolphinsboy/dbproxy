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

>
针对MASTER以及SLAVE两个都进行检测

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
		
		//使用IP作为主键，通过自定义函数，转换为guint
		
		
	```

**init\_db_user**
>初始化db_user

```bash
[DB_User_1]
db_username             = db_user
db_password             = db_pass 
default_db              = test
default_charset         = gbk 
cluster_name            = DBA_C_demo
```

```c
/*认字符编码是gbk_chinses_ci (28) */
user->default_charset = 28

```
对密码进行加密：

```c
user->scramble_len = 21; 
*(user->scramble_password) = '\x14'; 

scramble( 
user->scramble_password + 1,
	"\x2f\x55\x3e\x74\x50\x72\x6d\x4b\x56\x4c\x57\x54\x7c\x34\x2f\x2e\x37\x6b\x37\x6e",
	user->password);
```

机密函数：

```c
void scramble(char *to, const char *message, const char *password) {

  SHA1_CONTEXT sha1_context;
  uint8 hash_stage1[SHA1_HASH_SIZE];
  uint8 hash_stage2[SHA1_HASH_SIZE];

  mysql_sha1_reset(&sha1_context);
  /* stage 1: hash password */
  mysql_sha1_input(&sha1_context, (uint8 *) password, (uint) strlen(password));
  mysql_sha1_result(&sha1_context, hash_stage1);
  /* stage 2: hash stage 1; note that hash_stage2 is stored in the database */
  mysql_sha1_reset(&sha1_context);
  mysql_sha1_input(&sha1_context, hash_stage1, SHA1_HASH_SIZE);
  mysql_sha1_result(&sha1_context, hash_stage2);
  /* create crypt string as sha1(message, hash_stage2) */;
  mysql_sha1_reset(&sha1_context);
  mysql_sha1_input(&sha1_context, (const uint8 *) message, SCRAMBLE_LENGTH);
  mysql_sha1_input(&sha1_context, hash_stage2, SHA1_HASH_SIZE);
  /* xor allows 'from' and 'to' overlap: lets take advantage of it */
  mysql_sha1_result(&sha1_context, (uint8 *) to);
  my_crypt(to, (const uchar *) to, hash_stage1, SCRAMBLE_LENGTH);
}
```
加密这块再进一步的细节，还得持续研究。

连接DB的字符集

```c
user->default_charset = 28; /* gbk_chinese_ci */
user->default_charset = 33;  /* utf8_general_ci */
user->default_charset = 8;  /* latin1_swedish_ci */
user->default_charset = 63; /* binary */
```

**init\_product_user**

```
[Product_User_1]
username                = prod_user 
password                = prod_pass
db_username             = db_user
max_connections         = 100 

# Product User prod_user auth ip
authip_127.0.0.1=127.0.0.1
```

这里也涉及到密码转义的问题，和DB的密码处理方式一样。

需要按照db_username与上一个函数中产生的user进行对比

```c
d_user = g_hash_table_lookup(config->db_user, d_user_name)
```

对授权ip进行处理:

```c
user->auth_ips = g_ptr_array_new()

auth_ip *ip = NULL;
ip = calloc(1, sizeof(auth_ip))

inet_aton(value, &(ip->addr))

g_ptr_array_add(user->auth_ips, ip)
```

**AuthIP结构体**

```c
/**
 * @brief 验证IP
 */
typedef struct {
    /**< IP地址*/
    struct in_addr addr;
} auth_ip;
```

**init\_auth_ip**

```
# [global ip]
[Auth_IP_localhost]
ip=127.0.0.1
[Auth_IP_dba]
ip=10.23.252.150 
```

```c
#define CONFIG_AUTH_IP_IP "ip"
strncasecmp(CONFIG_AUTH_IP_IP, keys[j], strlen(CONFIG_AUTH_IP_IP))
 
//必须要使ip作为标记
 
 inet_aton(value, &(ip->addr))
 
 //把转换后的ip地址丢到config->auth_ips中
 g_ptr_array_add(config->auth_ips, ip)
```

记录配置文件的stat信息

```c
    struct stat conf_s;
    if(0 != stat(conf_path,&conf_s)){
    ¦   printf("read the status of %s failed",conf_path);
    ¦   return NULL;
    }    
    config->conf_modify_time = conf_s.st_mtime;
```

**截止到现在配置解析的部分已经结束**

####2.4 日志部分，创建日志的结构体

```c
(logger = logger_create(srv->config->log_dir,
    srv->config->log_filename, srv->config->log_maxsize,
    srv->config->log_level))
```

参数有四个：

+ 日志目录
+ 日志名称
+ 日志最大size
+ 日志的Level

对应的logger结构体如下：

```c
typedef struct{

    unsigned long int  maxsize;
    char *log_dir;
    char *log_filename;

    char *log_filepath;
    char *werror_log_filepath;
    char *load_log_filepath;

    char *log_filepath_tmp;
    char *werror_log_filepath_tmp;
    char *load_log_filepath_tmp;

    ino_t log_inode;
    ino_t werror_log_inode;
    ino_t load_log_inode;

    int fd;
    int werror_fd;
    int load_fd;

    int log_level;                            

} t_logger;
t_logger *logger;
```

日志对应的文件是:

```bash
log.h
log.c
```




