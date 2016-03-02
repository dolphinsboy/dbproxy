#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mysql.h>
#include <mysql_com.h>
#include "array.h"
#include "passwd.h"

typedef struct _HandshakeV10Packet{
    int protocolVersion;
    char serverVersion[10];
    int connectionId;
    unsigned char authPluginData[8];
    int capability;
    int characterSet;
    int statusFlag;
    unsigned char authPluginData2[13];
    char authPluginName[64];
}HandshakeV10Packet;

void readNullEndStr(char *body, char *p_str, int index){
    int j=0;
    while(body[index] != 0)
    {
        p_str[j++] = body[index];
        index++;
    }

}
int readConnectionId(char *body, int index){
    
    int conn_id;

    conn_id = body[index] & 0xff | (body[index+1] & 0xff) << 8 |
        ((body[index+2] & 0xff) << 16 ) |
        ((body[index+3] & 0xfff) << 24);

    printf("%d\n", index);
    return conn_id;
}

void readFixByte(char *body, int index, char *fix_array, int len){
    int i = 0;
    while(i < len){
        fix_array[i] = body[index+i];
        i++;
    }

}

int readFixShort(char *body, int index){
    int val;
    val = ((body[index]&0xff) | ((body[index+1] & 0xff) << 8));

    return val;
}

void buildHandshakePacket(char *body, HandshakeV10Packet* packet){

    int index = 4;
    int authPluginDataLen = 0;
    int len;

    //协议版本
    packet->protocolVersion = body[index];
    index++;

    //读取服务器端的MySQL版本,字符串类型,以\0结尾
    readNullEndStr(body, packet->serverVersion, index);
    index += sizeof(packet->serverVersion) + 1;

    //connectionId
    packet->connectionId = readConnectionId(body, index);
    index += 4;

    //auth-plugin-data-part-1
    readFixByte(body, index, packet->authPluginData, 8);
    index += 8;

    //一个字节的填充,filter
    index += 1;

    //capability的低2位
    packet->capability = readFixShort(body, index);
    index += 2;

    //charset
    packet->characterSet = body[index++];

    //status flags
    packet->statusFlag = readFixShort(body, index);
    index += 2;

    //capability的高2位
    packet->capability = readFixShort(body, index) << 16 | packet->capability;
    index += 2;

    //auth-plugin-data-part-2所占字节数
    if((packet->capability & CLIENT_PLUGIN_AUTH) != 0){
        len = body[index];
        index++;
        authPluginDataLen = len - 8;
    }

    printf("authPluginDataLen = %d\n", authPluginDataLen);

    //保留10个字节空间
    index += 10;

    //随机字符串
    if((packet->capability & CLIENT_SECURE_CONNECTION) != 0){

        len = 13 > authPluginDataLen ? 13 : authPluginDataLen;
        printf("len = %d\n", len);

        readNullEndStr(body,packet->authPluginData2,index);

        index += len;
    }

    //auth-plugin name

    if((packet->capability & CLIENT_PLUGIN_AUTH) != 0){
        readNullEndStr(body, packet->authPluginName,index);

        index = index + sizeof(packet->authPluginName) + 1;
    }
}

void print_packet(HandshakeV10Packet *packet){

    printf("ProtocolVersion= %d\n",packet->protocolVersion);
    printf("ServerVersion  = %s\n", packet->serverVersion);
    printf("ConnectionId   = %d\n", packet->connectionId);
    printf("Auth-plugin-data-part-1 = %s, size = %d\n", packet->authPluginData, sizeof(packet->authPluginData));

    int k;

    for(k = 0; k < 8;k++)
        printf("%x", packet->authPluginData[k]);
    printf("\n");
    printf("Auth-plugin-data-part-2 = %s, size = %d\n", packet->authPluginData2, sizeof(packet->authPluginData2));

    for(k = 0; k<12; k++)
        printf("%x", packet->authPluginData2[k]);
    printf("\n");

    printf("Auth-plugin-name = %s\n", packet->authPluginName);

}

void buildHandshakeResponse41(HandshakeV10Packet *packet, byte_array* arr){
    //capability flags, CLIENT_PROTOCOL_41 always set
    int capability = 1 | 4 | 512 | 8192 | 32768;
    byte_array_append_len(arr, (void *)(&capability), 4);

    //max-packet size
    int max_packet_size = 1 << 24;
    byte_array_append_len(arr, (void *)(&max_packet_size), 4);

    //charset set,utf8_general_ci
    unsigned char charset_set = 33;
    byte_array_append_len(arr, (void *)(&charset_set), 1);

    //reserved 23
    unsigned char reserved[23];
    memset(reserved, 0, sizeof(reserved));
    byte_array_append_len(arr, reserved, 23);

    //username
    char *p = "test";
    byte_array_append_len(arr, p, strlen(p));

    char end = '\x00';
    byte_array_append_len(arr, (void*)(&end), 1);

    //根据server返回的随机字符串以及密码生成sha1加密字符串
    unsigned char scramble_password[21];
    unsigned char random_key[21];
    memcpy(random_key, packet->authPluginData, 8);
    memcpy(random_key+8, packet->authPluginData2, 13);
    
    *scramble_password = '\x14';
    scramble(scramble_password+1,random_key, "test123");

    byte_array_append_len(arr, scramble_password, 21);

    //byte_array_append_len(arr, (void*)(&end), 1);
}

int main(){
    int socketfd;
    int ret;
    int n;
    char buf[128];
    int i;
    unsigned char sequence;
    struct sockaddr_in client_addr;
    socklen_t sock_len;

    byte_array *arr;
    byte_array *response_arr;

    HandshakeV10Packet *packet;
    packet = malloc(sizeof(HandshakeV10Packet));

    bzero(&client_addr, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &client_addr.sin_addr);
    client_addr.sin_port = htons(5627);
    //client_addr.sin_port = htons(4051);

    socketfd = socket(AF_INET, SOCK_STREAM, 0);

    if (socketfd < 0){
        perror("socket failed");
        exit(1);
    }

    ret = connect(socketfd, (struct sockaddr*)&client_addr, sizeof(client_addr));
    if(ret < 0){
        perror("connect failed");
        exit(1);
    }

    printf("connect result:%d\n", ret);
    n = recv(socketfd, buf, 128, 0);

    //sequence
    sequence = (unsigned char)(buf[3]) + 1;

    buildHandshakePacket(buf, packet);

    for(i = 0; i < n; i++)
        printf("\\x%x", buf[i]);
    printf("\n");

    print_packet(packet);

    //生成返回packet
    arr = byte_array_sized_new(128);
    buildHandshakeResponse41(packet, arr);

    //包头
    response_arr = byte_array_sized_new(256);

    short response_packet_len = arr->size + 4;
    byte_array_append_len(response_arr, (void *)(&response_packet_len), 2);
    unsigned char re = 0;
    byte_array_append_len(response_arr, (void *)(&re), 1);
    byte_array_append_len(response_arr, (void *)(&sequence), 1);

    byte_array_append_len(response_arr, arr->data, arr->size);

    for(i = 0; i < response_arr->size; i++)
        printf("\\x%02x", response_arr->data[i]);
    printf("\n");

    //发送响应包
    n = write(socketfd, response_arr->data, response_arr->size);
    //n = write(socketfd, arr->data, arr->size);

    //读取server的验证
    memset(buf, 0, sizeof(buf));
    n = read(socketfd, buf, 128);

    printf("read_n = %d\n", n);

    for(i = 0; i < n;i++)
        printf("\\x%02x",buf[i]);
    printf("\n");

    return 0;

}
