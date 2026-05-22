#ifndef __DEFVALS_H__
#define __DEFVALS_H__

#include <stdint.h>


#define SESSION_MAX_DURATION 0x24ea00   // 28 jours
#define KEY_MAX_DURATION 0x1e187e0   // 1 an (365.25j)
#define HASHED_PASSWD_LEN 64
#define MAX_USERNAME_LEN 32
#define MAX_KEY_LEN 128

#define PERMISSION_USER 2
#define PERMISSION_ELEVATED 1
#define PERMISSION_ADMIN 0

typedef struct session__s {
    uint64_t sessionId;
    uint64_t userId;
    uint64_t expiration_time;
    char *device_name;
} Session;

typedef struct userSessions_s {
    unsigned short nb_sessions;
    Session *sessions;
} UserSessions;


typedef struct user_s {
    uint64_t id;
    uint64_t key_exp_time;
    int32_t salt;
    char *username; // on initialise pas a MAX_USERNAME_LEN pck la chaine peut très bien etre plus courte, contrairement a passwd hashé oua la clé API
    char password[HASHED_PASSWD_LEN];
    char key[MAX_KEY_LEN];
    char permission_level;
} User;

#endif