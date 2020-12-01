#ifndef _WORKER_H_
#define _WORKER_H_

SSL_CTX *ctx;
SSL *ssl;

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

/**
 * @param: char *string, char** parsed_string
 * @description:Removes Whitespaces and creates an array of strings
 * @return:-
 */ 
int worker_check_command(char* message);

/**
 * @param: char *string, char** parsed_string
 * @description:Removes Whitespaces and creates an array of strings
 * @return: return an array with strings
 */ 
char **removeSpaces(char *string);

/**
 * @param:char **string
 * @description:Returns the size of an array of strings
 * @return:An integer which is the size of the array of strings
 */ 
int returnStringArraySize(char **string);

/**
 * @param:char **string, int i, int loginstatus
 * @description: Verifies if the login command has the correct format 
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int worker_checkLoginCommand(char **string, int i);

/**
 * @param:char **string, int i, int loginstatus
 * @description: Verifies if the login command has the correct format 
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int worker_checkRegisterCommand(char **string, int i);

/**
 * @param:int i, int loggin
 * @description: Verifies if the users command has the correct format 
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */   
int worker_checkUsersCommand(int i);

/**
 * @param:char **string, int in
 * @description:Verifies if the exit command has the correct format
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int checkExitCommand(char **string, int in);

/**
 * @param:char *string
 * @description:Parses the message send by the user(private and public)
 * @return: Returns an integer 1 for correct and 0 for incorrect
 */  
int parseMessage(char *string);

/**
 * @param:char *string
 * @description:The method removes whitespaces from the beginning and ending of a string 
 * @return: -
 */ 
void  remove_whitespaces(char *string);

/**
 * @param:char *string
 * @description:The method removes whitespaces from a private message
 * @return:-
 */ 
void remove_whitespaces_private(char *string);

/**
 * @param:char* string
 * @description:Contains all the commands that the UI accepts
 * @return:Returns an integer coresponting with the command found
 */ 
int stack_of_commands(char* string);

/**
 * @param:char* string
 * @description:Verifies if the username has the wanted length and characters
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int verify_username(char* string);

/**
 * @param:char* string
 * @description:Verifies if the password has the wanted length and characters
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int verify_password(char* string);

/**
 * @param:char* string
 * @description:Verifies if the message has the allowed characters
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int verify_message(char* string);


/**
 * @param:char* string
 * @description:Verifies if there are any bruteforce attempts and 
 *              puts the worker to sleep if it finds any.
 * @return:-
 */ 
void bruteforce_check();


#endif /* !defined(_WORKER_H_) */
