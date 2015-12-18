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


