//
// Created by nuru on 11/22/20.
//

#ifndef SECURECHAT2020_CHATDB_H
#define SECURECHAT2020_CHATDB_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <time.h>

#define DB_NAME "chat.db"

char *db_sql;
sqlite3 *db;
sqlite3_stmt *db_stmt;
int db_rc;

int create_tables();

int create_user(char *username, char *password, int fd, SSL *ssl);

int check_login(char *username, char *password, int fd, SSL *ssl);

char *retrieve_last(char *username);

int process_global(char *received, char *username);

int process_private(char *fullmsg, char *recipient, char *curr_user);

char* send_all_messages(int fd, char *username, SSL *ssl);

int set_logged_in(char *current_user);

char *retrieve_all_users();

void logout_user(char *current_user);

char *get_current_time(void);

int user_exists(char *username);

#endif //SECURECHAT2020_CHATDB_H
