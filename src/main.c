#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "../include/db_utils.h"
#include "../include/ciphr_mg.h"
#include "../include/defVals.h"

/*
auth ("
	id BIGINT PRIMARY KEY
   	username VARCHAR(32) UNIQUE,
    salt CHARACTER(16),
    passwd CHARACTER(32),
    key CHARACTER(64) NOT NULL UNIQUE
    key_exp_time CHARACTER(20)
    permission_level TINYINT
    )

sessions ("
	session_id BIGINT
   	user_id BIGINT NOT NULL
    expiration_time CHARACTER(20) NOT NULL
    device_name VARCHAR(32)
    FOREIGN KEY (user_id) REFERENCES auth(id)
    PRIMARY KEY (session_id, user_id
    */

void hashToTab(uint64_t *tab, char *hash)
{
    memcpy(tab, hash, sizeof(uint64_t) * (SHA256_DIGEST_LENGTH / 8));
}

void test(void)
{
    const char *password = "monMotDePasse123";
    char hashed[2 * (16 + SHA256_DIGEST_LENGTH) + 1]; // Taille suffisante pour sel + hash

    hash_with_salt(password, hashed, sizeof(hashed));
    printf("Chaîne hashée + sel : %s\n", hashed);
}


void printSession(Session *s)
{
    printf("printSession: userId:%ld\tsessionId:%ld\tname:%s\texpiration_time:%ld\n", s->userId, s->sessionId, s->device_name, s->expiration_time - time(NULL));
    return;
}


int main(void)
{
    char salt[16];
    generateSalt(salt);
    for (int i = 0; i < 16; i++)
    {
        printf("%d ", salt[i]);
    }
    printf("\n");
    
    return 0;
    sqlite3 *db;
    sqlite3_open_v2("./test.db", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (!db)
        return 1;

    checkTableAuth(db);
    checkTableSession(db);

    insertToAuth(db, 2, NULL, "passwd", "kkkkkk", time(NULL) + KEY_MAX_DURATION, 0);
    insertToSession(db, 2, 1, "Linux");
    printSession(&getUserSessions(db, 2)->sessions[0]);
    printf("userid of key kkkkkk :%ld\n", getUserIdFromKey(db, "kkkkkk"));
    //deleteUser(db, 2);
    deleteSession(db, 1);

    sqlite3_close_v2(db);
    return 0;
}