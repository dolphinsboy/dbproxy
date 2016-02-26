#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mysql.h>
#include <mysql_com.h>

typedef struct _HandshakeV10Packet_T{
    int protocolVersion;
    char serverVersion[10];
    int connectionId;
    char authPluginData[9];
    int capability;
    int characterSet;
    int statusFlag;
    char authPluginData2[64];
    char authPluginName[64];
}HandshakeV10Packet_T;

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

void buildHandshakePacket(char *body, HandshakeV10Packet_T* packet){

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

void print_packet(HandshakeV10Packet_T *packet){

    printf("ProtocolVersion= %d\n",packet->protocolVersion);
    printf("ServerVersion  = %s\n", packet->serverVersion);
    printf("ConnectionId   = %d\n", packet->connectionId);
    printf("Auth-plugin-data-part-1 = %s\n", packet->authPluginData);
    printf("Auth-plugin-data-part-2 = %s\n", packet->authPluginData2);
    printf("Auth-plugin-name = %s\n", packet->authPluginName);

}

int main(){
    int socketfd;
    int ret;
    int n;
    char buf[128];
    int i;
    struct sockaddr_in client_addr;
    socklen_t sock_len;

    HandshakeV10Packet_T *packet;
    packet = malloc(sizeof(HandshakeV10Packet_T));

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

    buildHandshakePacket(buf, packet);

    for(i = 0; i < n; i++)
        printf("\\x%x", buf[i]);
    printf("\n");

    print_packet(packet);

    return 0;

}
