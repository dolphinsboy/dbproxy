#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    unsigned char buf[2];

    unsigned char c = 'r';
    memcpy(buf,(void*)(&c), sizeof(char));

    printf("\\x%x\n", buf[0]);

    printf("int size = %d\n", sizeof(int));
    printf("short int size = %d\n", sizeof(short int));

    unsigned char buf2[5];

    char *p = "root";
    memcpy(buf2,(void*)p, 5);

    int i=0;

    for(i = 0; i < sizeof(buf2); i++)
        printf("\\x%02x", buf2[i]);
    printf("\n");

    return 0;
}
