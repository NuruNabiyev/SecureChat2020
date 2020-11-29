
#include "chatdb.h"
#include "util.h"

/**
 * Opens db and creates tables if do not exist
 * @return 1 on success, 0 on fail
 */
int create_tables() {
  // create database
  db_rc = sqlite3_open(DB_NAME, &db);
  if (db_rc != SQLITE_OK) {
    puts("Could not create database");
    return 0;
  }

  // create chat table where registered users will be stored
  sqlite3_prepare_v2(db, "CREATE TABLE IF NOT EXISTS \"global_chat\" ("
                         "\"id\" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,"
                         "\"sender\" TEXT NOT NULL,"
                         // username or NULL for global
                         "\"recipient\" TEXT,"
                         "\"message\" TEXT NOT NULL"
                         ");",
                     -1, &db_stmt, NULL);
  db_rc = sqlite3_step(db_stmt);
  if (db_rc != SQLITE_DONE) {
    printf("ERROR creating global chat: %s\n", sqlite3_errmsg(db));
    return 0;
  }

  // create users table where registered users will be stored
  sqlite3_prepare_v2(db, "CREATE TABLE IF NOT EXISTS \"users\" ("
                         "\"username\" TEXT NOT NULL PRIMARY KEY UNIQUE,"
                         "\"hash_pwd\" TEXT NOT NULL,"
                         "\"salt_pwd\" TEXT NOT NULL,"
                         // 1 if true, 0 if offline
                         "\"is_logged_in\" INTEGER NOT NULL"
                         ");",
                     -1, &db_stmt, NULL);
  db_rc = sqlite3_step(db_stmt);

  if (db_rc != SQLITE_DONE) {
    printf("ERROR creating users: %s\n", sqlite3_errmsg(db));
    return 0;
  }

  // set all logged in to false
  db_sql = "UPDATE users set is_logged_in = 0 where username IS NOT NULL;";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  db_rc = sqlite3_step(db_stmt);
  sqlite3_finalize(db_stmt);

  return 1;
}

/**
 * Adds user into DB
 * @return 1 on success, 0 if error
 */
int create_user(char *username, char *password, int fd, SSL *ssl) {
  db_rc = sqlite3_open(DB_NAME, &db);

  db_sql = "SELECT COUNT(*) FROM users WHERE username = ?1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int user_exists = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    user_exists = sqlite3_column_int(db_stmt, 0);
  }
  sqlite3_finalize(db_stmt);

  if (user_exists == 0) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char new_salt[SHA256_DIGEST_LENGTH];
    RAND_bytes(new_salt, sizeof(new_salt));
    hash_password(password, hash, new_salt);

    // add user to table
    db_sql = "INSERT INTO users (username, hash_pwd, salt_pwd, is_logged_in) "
             "VALUES (?1, ?2, ?3, ?4);";
    sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
    sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(db_stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(db_stmt, 3, new_salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(db_stmt, 4, 1);  // make user online
    db_rc = sqlite3_step(db_stmt);
    sqlite3_finalize(db_stmt);
    if (db_rc == SQLITE_DONE) {
      // send to client
      char *register_ok = "registration succeeded\n";
      ssl_block_write(ssl, fd, register_ok, strlen(register_ok));
      return 1;
    } else {
      printf("ERROR inserting data: %s\n", sqlite3_errmsg(db));
      char *registration_fail = "error: please try again\n";
      ssl_block_write(ssl, fd, registration_fail, strlen(registration_fail));
    }

  } else {
    // send to client
    char *registration_fail = "error: user already exists\n";
    ssl_block_write(ssl, fd, registration_fail, strlen(registration_fail));
  }
  return 0;
}

int check_login(char *username, char *password, int fd, SSL *ssl) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT * FROM users WHERE username = ?1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int password_matches = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const char *hash = sqlite3_column_text(db_stmt, 1);
    const char *salt = sqlite3_column_text(db_stmt, 2);
    unsigned char check_hash[SHA256_DIGEST_LENGTH];
    hash_password(password, check_hash, salt);

    if (memcmp(hash, check_hash, SHA256_DIGEST_LENGTH) == 0) {
      password_matches = 1;
    }
  }
  sqlite3_finalize(db_stmt);

  if (password_matches == 1) {
    char *text = "authentication succeeded\n";
    ssl_block_write(ssl, fd, text, strlen(text));
    return 1;
  } else {
    // send error to client
    char *login_fail = "error: invalid credentials\n";
    ssl_block_write(ssl, fd, login_fail, strlen(login_fail));
  }
  return 0;
}

/**
 * Retrieves last message from db and sends to client
 * @param fd client fd
 */
char *retrieve_last(char *username) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT message FROM global_chat "
           "where recipient IS NULL or recipient == ?1 or sender == ?1"
           "ORDER by id DESC LIMIT 1;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  // will be looped once
  char *last_msg = malloc(300);
  int is_any = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const unsigned char * db_msg = sqlite3_column_text(db_stmt, 0);
    sprintf(last_msg, "%s", db_msg);
    is_any = 1;
  }
  sqlite3_finalize(db_stmt);
  if (is_any == 0) return NULL;
  return last_msg;
}

/**
 * Inserts global message to db
 * @return -1 if failed, 1 if all ok and proceed to notify workers
 */
int process_global(char *received, char *username) {
  char *curr_time = NULL;
  char *main_msg = NULL;
  curr_time = get_current_time();
  main_msg = (char *) malloc(strlen(received) + strlen(curr_time) + strlen(username) + 3);
  sprintf(main_msg, "%s %s: %s\n", curr_time, username, received);

  db_rc = sqlite3_open(DB_NAME, &db);
  if (db_rc != SQLITE_OK) {
    puts("Could not open database");
    return -1;
  }

  db_sql = "INSERT INTO global_chat (sender, recipient, message) "
           "VALUES (?1, ?2, ?3);";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);
  sqlite3_bind_text(db_stmt, 2, NULL, -1, SQLITE_STATIC);
  sqlite3_bind_text(db_stmt, 3, main_msg, -1, SQLITE_STATIC);
  db_rc = sqlite3_step(db_stmt);
  sqlite3_finalize(db_stmt);

  if (db_rc == SQLITE_DONE) {
    free(main_msg);
    return 1;
  } else {
    printf("ERROR in adding message to table: %s\n", sqlite3_errmsg(db));
  }

  return 0;
}

int process_private(char *fullmsg, char *recipient, char *curr_user) {
  // if users same - return error
  if (strcmp(recipient, curr_user) == 0) {
    printf("Same recipient and sender\n");
    return -1;
  }

  char *curr_time = get_current_time();
  char *main_msg = (char *) malloc(500);
  sprintf(main_msg, "%s %s: %s\n", curr_time, curr_user, fullmsg);

  db_rc = sqlite3_open(DB_NAME, &db);
  if (db_rc != SQLITE_OK) {
    puts("Could not open database");
    return -1;
  }

  db_sql = "INSERT INTO global_chat (sender, recipient, message) "
           "VALUES (?1, ?2, ?3);";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, curr_user, -1, SQLITE_STATIC);
  sqlite3_bind_text(db_stmt, 2, recipient, -1, SQLITE_STATIC);
  sqlite3_bind_text(db_stmt, 3, main_msg, -1, SQLITE_STATIC);
  db_rc = sqlite3_step(db_stmt);
  sqlite3_finalize(db_stmt);

  // send to recipient and current user
  if (db_rc == SQLITE_DONE) {
    free(main_msg);
    return 1;
  } else {
    printf("ERROR in adding message to table: %s\n", sqlite3_errmsg(db));
    return -1;
  }
}

/**
 * Query all messages and send to that client
 * @return last sent message
 */
char* send_all_messages(int fd, char *username, SSL *ssl) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT message FROM global_chat "
           "where recipient IS NULL or recipient == ?1 or sender == ?1;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  // todo gather to single payload and send?
  char *last_msg = malloc(300);
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    unsigned const char *curr_msg = sqlite3_column_text(db_stmt, 0);
    ssl_block_write(ssl, fd, curr_msg, strlen(curr_msg));
    sprintf(last_msg, "%s", curr_msg);
  }
  sqlite3_finalize(db_stmt);
  return last_msg;
}

int set_logged_in(char *current_user) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "UPDATE users set is_logged_in = ?1 where username = ?2;";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_int(db_stmt, 1, 1);
  sqlite3_bind_text(db_stmt, 2, current_user, -1, SQLITE_STATIC);
  db_rc = sqlite3_step(db_stmt);

  if (db_rc != SQLITE_DONE) {
    printf("ERROR updating data: %s\n", sqlite3_errmsg(db));
    return -1;
  }
  sqlite3_finalize(db_stmt);
  return 1;
}

char *retrieve_all_users() {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT * FROM users WHERE is_logged_in IS 1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);

  char logged_in_users[5000] = "";
  strcpy(logged_in_users, "Logged in users: ");

  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const unsigned char *curr_user = sqlite3_column_text(db_stmt, 0);
    strcat(logged_in_users, curr_user);
    strcat(logged_in_users, ", ");
  }
  // remove last coma
  size_t ln = strlen(logged_in_users) - 2;
  if (logged_in_users[ln] == ',') {
    logged_in_users[ln] = '\n';
    logged_in_users[ln + 1] = '\0';
  }
  sqlite3_finalize(db_stmt);

  char *users = (char *) malloc(sizeof(char *) * (strlen(logged_in_users) + 2));
  strncpy(users, logged_in_users, strlen(logged_in_users) + 1);
  return users;
}

void logout_user(char *current_user) {
  // make is_logged_in false for this user
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "UPDATE users set is_logged_in = ?1 where username = ?2;";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_int(db_stmt, 1, 0);
  sqlite3_bind_text(db_stmt, 2, current_user, -1, SQLITE_STATIC);
  db_rc = sqlite3_step(db_stmt);

  if (db_rc != SQLITE_DONE) {
    printf("ERROR updating data: %s\n", sqlite3_errmsg(db));
  }
  sqlite3_finalize(db_stmt);
}

char *get_current_time(void) {
  time_t rawtime;
  struct tm *timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  // 2019-11-01 09:30:00
  char *time = (char *) malloc(29 * sizeof(char));
  sprintf(time, "%d-%02d-%02d %02d:%02d:%02d",
          timeinfo->tm_year + 1900,
          timeinfo->tm_mon + 1,
          timeinfo->tm_mday,
          timeinfo->tm_hour,
          timeinfo->tm_min,
          timeinfo->tm_sec);
  return time;
}

/**
 * Checks user's online status
 * @param username
 * @return 0 if user not found OR offline, 1 if offline
 */
int user_exists(char *username) {
  db_sql = "SELECT COUNT(*) FROM users WHERE username = ?1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int user_online = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    user_online = sqlite3_column_int(db_stmt, 0);
  }
  sqlite3_finalize(db_stmt);

  return user_online;
}