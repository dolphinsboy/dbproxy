#ifndef _PASSWD_H_
#define _PASSWD_H_

#define SCRAMBLE_LENGTH 20
#define SHA1_HASH_SIZE 20

int make_rand_scram(char *scram, int len);
void scramble(char *to, const char *message, const char *password);

#endif
