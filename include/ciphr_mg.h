#ifndef __CIPHR_MG_H__
#define __CIPHR_MG_H__

#include <openssl/sha.h>
#include <stdio.h>

void XORShift128(char val[16]);
void generateSalt(char salt[16]);
void hash(char *input, char hash[SHA256_DIGEST_LENGTH], char salt[16], bool saltIsEmpty);

#endif