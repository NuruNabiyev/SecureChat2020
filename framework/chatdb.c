
#include "chatdb.h"

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
                         //                         "\"timestamp\" TEXT NOT NULL,"
                         //                         "\"from_user\" TEXT NOT NULL,"
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
int create_user(char *username, char* password, int fd) {
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
    // add user to table
    db_sql = "INSERT INTO users (username, hash_pwd, is_logged_in) "
             "VALUES (?1, ?2, ?3);";
    sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
    sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(db_stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_int(db_stmt, 3, 1);  // make user online
    db_rc = sqlite3_step(db_stmt);
    sqlite3_finalize(db_stmt);
    if (db_rc == SQLITE_DONE) {
      // send to client
      char *register_ok = "You have been registered!";
      send(fd, register_ok, strlen(register_ok), 0);
      return 1;
    } else {
      printf("ERROR inserting data: %s\n", sqlite3_errmsg(db));
      char *registration_fail = "error: please try again\n";
      send(fd, registration_fail, strlen(registration_fail), 0);
    }

  } else {
    // send to client
    char *registration_fail = "error: user already exists\n";
    send(fd, registration_fail, strlen(registration_fail), 0);
  }
  return 0;
}

int check_login(char *username, char* password, int fd) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT * FROM users WHERE username = ?1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int password_matches = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const char *sql_pwd = sqlite3_column_text(db_stmt, 1);
    if (strcmp(password, sql_pwd) == 0) {
      password_matches = 1;
    }
  }
  sqlite3_finalize(db_stmt);

  if (password_matches == 1) {
    char *text = "You have been logged in!";
    send(fd, text, strlen(text), 0);
    return 1;
  } else {
    // send error to client
    char *login_fail = "error: invalid credentials\n";
    send(fd, login_fail, strlen(login_fail), 0);
  }
  return 0;
}

/**
 * Retrieves last message from db and sends to client
 * TODO should retrieve and delegate sending to worker (e.g. return string)
 * @param fd client fd
 */
void broadcast_last(int fd) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT message FROM global_chat ORDER by id DESC LIMIT 1;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);

  // will be looped once
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const unsigned char *last_msg = sqlite3_column_text(db_stmt, 0);
    // todo would be great not to handle sends in this loop, delegate to worker
    int send_i = send(fd, last_msg, strlen(last_msg), 0);
    printf("replied %i bytes\n", send_i);
  }
  sqlite3_finalize(db_stmt);
}

/**
 * Inserts global message to db
 * @return -1 if failed, 1 if all ok and proceed to notify workers
 */
int insert_global(char *received) {
  char *curr_time = get_current_time();
  char *user = "group 9:";  //todo extract from db
  char *main_msg = (char *) malloc(strlen(received) + strlen(curr_time) + strlen(user));
  sprintf(main_msg, "%s %s %s\n", curr_time, user, received);

  db_rc = sqlite3_open(DB_NAME, &db);
  if (db_rc != SQLITE_OK) {
    puts("Could not open database");
    return -1;
  }

  // SQL Query vulnerable to SQL Injection, will fix with parameterised query
  // using sqlite3_bind_text() in coming deadline.
  char *sql_format = "INSERT INTO global_chat (message) VALUES (\"%s\");";
  db_sql = (char *) malloc(strlen(sql_format) + strlen(main_msg));
  sprintf(db_sql, sql_format, main_msg);
  sqlite3_prepare_v2(db, db_sql, (int) strlen(db_sql), &db_stmt, NULL);
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

/**
 * Query all messages and send to that client
 * @return 0 on success
 */
int send_all_messages(int fd) {
  db_rc = sqlite3_open(DB_NAME, &db);
  char *db_sql = "SELECT message FROM global_chat;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);

  // todo gather to single payload and send?
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    unsigned const char *curr_msg = sqlite3_column_text(db_stmt, 0);
    send(fd, curr_msg, strlen(curr_msg), 0);
  }
  sqlite3_finalize(db_stmt);
  return 0;
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

void logout_user(char * current_user) {
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