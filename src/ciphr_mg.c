#include "../include/ciphr_mg.h"

#include <string.h>

void XORShift128(char val[16])
{
    uint64_t p1, p2, pt;

    memcpy(&p1, val, sizeof(uint64_t));
    memcpy(&p2, val + (sizeof(char) * 8), sizeof(uint64_t));

    pt = p1;
    pt ^= pt << 13;
    pt ^= pt >> 7;
    pt ^= pt << 17;
    p2 = pt;

    pt = p2;
    pt ^= pt << 13;
    pt ^= pt >> 7;
    pt ^= pt << 17;
    p1 = pt;

    memcpy(val, &p1, sizeof(uint64_t));
    memcpy(val + (sizeof(char) * 8), &p2, sizeof(uint64_t));
}

void generateSalt(char salt[16])
{
    static char default_rd[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    FILE *rd = fopen("/dev/urandom", "rb");
    if (rd)
        fread(salt, 1, 16, rd);

    else
    {
        char tmp[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        if (!memcmp(default_rd, tmp, sizeof(char) * 16))
            memcpy(default_rd, &generateSalt, sizeof(long));
    
        XORShift128(default_rd);
        memcpy(salt, default_rd, sizeof(char) * 16);
    }
}


void hash(char *input, char hash[SHA256_DIGEST_LENGTH], char salt[16], bool saltIsEmpty)
{
    size_t input_len = strlen(input);
    size_t salted_input_len = input_len + sizeof(salt);
    unsigned char *salted_input = malloc(salted_input_len);

    if(saltIsEmpty)
        generateSalt(salt);

    memcpy(salted_input, input, input_len);
    memcpy(salted_input + input_len, salt, sizeof(salt));

    SHA256(salted_input, salted_input_len, hash);

    free(salted_input);
}