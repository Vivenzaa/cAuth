#ifndef __DB_UTILS_H__
#define __DB_UTILS_H__

#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "defVals.h"


void checkTableAuth(sqlite3 *db);
void checkTableSession(sqlite3 *db);
bool insertToAuth(sqlite3 *db, uint64_t id, char *username, char *password, char *key, uint64_t key_exp_time, char permission_level);
bool insertToSession(sqlite3 *db, int64_t user_id, int64_t sessionId, char *device_name);
uint64_t getUserIdFromKey(sqlite3 *db, char *key);
UserSessions *getUserSessions(sqlite3 *db, uint64_t userId);
void deleteUser(sqlite3 *db, uint64_t userId);
void deleteSession(sqlite3 *db, uint64_t sessionId);

#endif