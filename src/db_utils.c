#include "../include/db_utils.h"
#include "../include/ciphr_mg.h"



void checkTableAuth(sqlite3 *db)
{
    if(!db)
        return;

    //const char *checkTable = "SELECT name FROM sqlite_master WHERE type='table' AND name='auth'";
    const char *checkTableAuth = "CREATE TABLE IF NOT EXISTS auth ("
	"id BIGINT PRIMARY KEY,"
   	"username VARCHAR(32) UNIQUE,"
    "salt CHARACTER(16)"
    "passwd CHARACTER(32),"
    "key CHARACTER(128) NOT NULL UNIQUE,"
    "key_exp_time BIGINT,"
    "permission_level TINYINT"
    ");";

    sqlite3_stmt *req = NULL;
    int errcode = sqlite3_prepare_v2(db, checkTableAuth, -1, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("checkTableAuth: prepare error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    errcode = sqlite3_step(req);
    if (errcode != SQLITE_DONE)
    {
        printf("checkTableAuth: step error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_finalize(req);
}

void checkTableSession(sqlite3 *db)
{
    if (!db)
        return;

    const char *checkTableSession = "CREATE TABLE IF NOT EXISTS sessions ("
	"session_id BIGINT PRIMARY KEY,"
   	"user_id BIGINT NOT NULL,"
    "expiration_time BIGINT,"
    "device_name VARCHAR(32),"
    "FOREIGN KEY (user_id) REFERENCES auth(id),"
    ");";

    sqlite3_stmt *req = NULL;

    int errcode = sqlite3_prepare_v2(db, checkTableSession, -1, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("checkTableSession: prepare error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    errcode = sqlite3_step(req);
    if (errcode != SQLITE_DONE)
    {
        printf("step error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_finalize(req);
}

bool insertToAuth(sqlite3 *db, uint64_t id, char *username, char *password, char *key, uint64_t key_exp_time, char permission_level)
{
    if (!db)
        return 0;

    char *base_req = "INSERT INTO auth (id, username, salt, passwd, key, key_exp_time, permission_level) VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *req = NULL;
    int errcode = sqlite3_prepare_v2(db, base_req, -1, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("insertToAuth: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return false;
    }

    char salt[16];
    char hashed[SHA256_DIGEST_LENGTH];
    if (password)
        hash(password, hashed, salt, true);
    

    sqlite3_bind_int(req, 1, id);
    sqlite3_bind_text(req, 2, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(req, 3, salt, 16, SQLITE_STATIC);
    sqlite3_bind_text(req, 4, hashed, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
    sqlite3_bind_text(req, 5, key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(req, 6, key_exp_time);
    sqlite3_bind_int(req, 7, permission_level);


    errcode = sqlite3_step(req);
    if (errcode != SQLITE_DONE)
    {
        printf("insertToAuth: step error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_finalize(req);
    return true;
}

bool insertToSession(sqlite3 *db, int64_t user_id, int64_t sessionId, char *device_name)    // pas complet, faut générer expiration time aussi
{
    if (!db)
        return false;

    char *base_req = "INSERT INTO sessions (session_id, user_id, expiration_time, device_name) VALUES (?, ?, ?, ?);";
    sqlite3_stmt *req = NULL;
    int errcode = sqlite3_prepare_v2(db, base_req, -1, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("insertToSession: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_int64(req, 1, sessionId);
    sqlite3_bind_int64(req, 2, user_id);
    sqlite3_bind_int64(req, 3, time(NULL) + SESSION_MAX_DURATION);
    sqlite3_bind_text(req, 4, device_name, -1, SQLITE_STATIC);

    errcode = sqlite3_step(req);
    if (errcode != SQLITE_DONE)
    {
        printf("insertToSession: step error, code:%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_finalize(req);

    return true;
}

uint64_t getUserIdFromKey(sqlite3 *db, char *key)
{
    if (!db || !key)
        return false;

    uint64_t ret = 0;
    char *base_req = "SELECT id FROM auth WHERE key LIKE ?;";
    sqlite3_stmt *req = NULL;
    int errcode = sqlite3_prepare_v2(db, base_req, 38, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("getUserIdFromKey: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_text(req, 1, key, -1, SQLITE_STATIC);

    errcode = sqlite3_step(req);
    switch (errcode){
        case SQLITE_ROW:
            ret = sqlite3_column_int64(req, 0);
            break;

        default:
            printf("getUserIdFromKey: step error, code:%d\n", errcode);
            printf("%s\n", sqlite3_errmsg(db));
            return 0;
    }
    sqlite3_finalize(req);

    return ret;
}

UserSessions *getUserSessions(sqlite3 *db, uint64_t userId)
{
    if (!db || !userId)
        return NULL;

    UserSessions *s = malloc(sizeof(UserSessions));
    if (!s)
        return NULL;
    s->nb_sessions = 0;
    s->sessions = NULL;
    char *base_req = "SELECT * FROM sessions WHERE user_id = ?;";
    sqlite3_stmt *req = NULL;

    int errcode = sqlite3_prepare_v2(db, base_req, 42, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("getUserSession: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(req, 1, userId);

    errcode = sqlite3_step(req);
    while(errcode != SQLITE_DONE)
    {
        uint64_t tmp_sessionId =        sqlite3_column_int64(req, 0);
        uint64_t tmp_userId =           sqlite3_column_int64(req, 1);
        uint64_t tmp_expiration_time =  sqlite3_column_int64(req, 2);
        char *tmp_device_name = (char *) sqlite3_column_text(req, 3);

        s->sessions = realloc(s->sessions, sizeof(Session) * (++s->nb_sessions));
        if (!s->sessions)
        {
            free(s);
            return NULL;
        }

        Session *current = &s->sessions[s->nb_sessions-1];

        current->sessionId = tmp_sessionId;
        current->userId = tmp_userId;
        current->expiration_time = tmp_expiration_time;

        current->device_name = malloc(sizeof(char) * (strlen(tmp_device_name) + 1));
        strcpy(current->device_name, tmp_device_name);

        errcode = sqlite3_step(req);
    }

    sqlite3_finalize(req);
    return s;
}


void deleteUser(sqlite3 *db, uint64_t userId)
{
    if (!db)
        return;

    char *base_req_auth = "DELETE FROM auth WHERE id = ?;";
    char *base_req_session = "DELETE FROM sessions WHERE user_id = ?;";
    sqlite3_stmt *req_auth = NULL;
    sqlite3_stmt *req_sessions = NULL;
    int errcode = sqlite3_prepare_v2(db, base_req_auth, 31, &req_auth, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("deleteUser__auth: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }
    errcode = sqlite3_prepare_v2(db, base_req_session, 40, &req_sessions, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("deleteUser__sessions: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int64(req_auth, 1, userId);
    sqlite3_bind_int64(req_sessions, 1, userId);

    sqlite3_step(req_auth);
    sqlite3_step(req_sessions);

    sqlite3_finalize(req_auth);
    sqlite3_finalize(req_sessions);
}



void deleteSession(sqlite3 *db, uint64_t sessionId)
{
    if (!db)
        return;

    char *base_req = "DELETE FROM sessions WHERE session_id = ?;";
    sqlite3_stmt *req = NULL;
    int errcode = sqlite3_prepare_v2(db, base_req, 43, &req, NULL);
    if (errcode != SQLITE_OK)
    {
        printf("deleteUser__auth: prepare error, code :%d\n", errcode);
        printf("%s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int64(req, 1, sessionId);

    sqlite3_step(req);
    sqlite3_finalize(req);
}