#ifndef _WORKER_H_
#define _WORKER_H_

SSL_CTX *ctx;
SSL *ssl;

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

int worker_check_command(char* message);

//Removes Whitespaces and returns a array of strings
char **worker_removeSpaces(char *string);

//Returns the size of an array of strings
int worker_returnStringArraySize(char **string);

//Verifies the login command
int worker_checkLoginCommand(char **string, int i);

//Verifies the register command
int worker_checkRegisterCommand(char **string, int i);

//Verifies the users command 
int worker_checkUsersCommand(int i);

//Verifies the exit command
int worker_checkExitCommand(char **string, int in);

//Parses the message send by the user(verifies if it is public and it's format) 
int worker_parseMessage(char *string);

//Modifies a string by removing his end of line character as a message cannot have a end of line
void worker_removeNewLine(char *string);


int worker_stack_of_commands(char* string);


#endif /* !defined(_WORKER_H_) */
