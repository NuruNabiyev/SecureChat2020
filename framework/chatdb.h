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

#include "ssl-nonblock.h"

#define DB_NAME "chat.db"

char *db_sql;
sqlite3 *db;
sqlite3_stmt *db_stmt;
int db_rc;

/**
 * @param: -
 * @description: Creates a 
 * @return:Returns an integer 1 for succesful execution and 0 for incorrect one 
 */ 
int create_tables();

/**
 * @param: char *username, char *password, int fd, SSL *ssl
 * @description: Creates a user
 * @return:Returns an integer 1 for succesful execution and 0 for incorrect one  
 */ 
int create_user(char *username, char *password, int fd, SSL *ssl);

/**
 * @param: char *username, char *password, int fd, SSL *ssl
 * @description: Verifies if a user is logged in
 * @return:Returns an integer 1 for succesful authentification and 0 for an incorrect one  
 */ 
int check_login(char *username, char *password, int fd, SSL *ssl);

/**
 * @param: char *username
 * @description: Gets the last message fromt the database
 * @return: A string   
 */
char *retrieve_last(char *username);

/**
 * @param: char *received, char *username
 * @description: Handles the public messages
 * @return: Returns an integer 1 for succesful execution and 0 for incorrect one 
 */ 
int process_global(char *received, char *username);

/**
 * @param: char *fullmsg, char *recipient, char *curr_user
 * @description: Handles the private messages
 * @return: Returns an integer 1 for succesful execution and 0 for incorrect one 
 */ 
int process_private(char *fullmsg, char *recipient, char *curr_user);

/**
 * @param: int fd, char *username, SSL *ssl
 * @description: Retrives and sends all the messages to the users
 * @return: Returns an array 
 */ 
char* send_all_messages(int fd, char *username, SSL *ssl);

/**
 * @param: char *current_user
 * @description: Sets logged in status to true to a account
 * @return: Returns an integer 1 for succesful execution and 0 for incorrect one 
 */ 
int set_logged_in(char *current_user);

/**
 * @param: -
 * @description: Retrives all logged in users
 * @return: Returns an array with users
 */ 
char *retrieve_all_users();

/**
 * @param: char *current_user
 * @description: Logs out the current user
 * @return: -
 */ 
void logout_user(char *current_user);

/**
 * @param: -
 * @description: Retrives the current time and date
 * @return: Returns an array with the timestamp
 */ 
char *get_current_time(void);

/**
 * @param: char *username
 * @description: Verifies if a user actual exists
 * @return: Returns an integer, 1 if it does and 0 if it does not
 */ 
int user_exists(char *username);
/**
 * @param: char *username
 * @description: Verifies if a user is logged in
 * @return: Returns an integer, 1 if it is and 0 if it is not
 */
int user_logged_in(char *username);

#endif //SECURECHAT2020_CHATDB_H
