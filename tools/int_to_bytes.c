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

    return 0;
}
