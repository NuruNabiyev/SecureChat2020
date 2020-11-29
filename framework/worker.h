#ifndef _WORKER_H_
#define _WORKER_H_

SSL_CTX *ctx;
SSL *ssl;

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

int worker_check_command(char* message);

//Removes Whitespaces and returns a array of strings
char **removeSpaces(char *string);

//Returns the size of an array of strings
int returnStringArraySize(char **string);

//Verifies the login command
int worker_checkLoginCommand(char **string, int i);

//Verifies the register command
int worker_checkRegisterCommand(char **string, int i);

//Verifies the users command 
int worker_checkUsersCommand(int i);

//Verifies the exit command
int checkExitCommand(char **string, int in);

//Parses the message send by the user(verifies if it is public and it's format) 
int parseMessage(char *string);

//Modifies a string by removing his end of line character as a message cannot have a end of line
void removeNewLine(char *string);


int stack_of_commands(char* string);


#endif /* !defined(_WORKER_H_) */
