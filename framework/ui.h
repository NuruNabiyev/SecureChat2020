#ifndef _UI_H_
#define _UI_H_

struct ui_state {
  /* TODO add fields to store the command arguments */
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

//The mothod verifies the command that was inserted by the user
void checkCommand(char* string,int loginStatus);

//Removes Whitespaces and returns a array of strings
char** removeSpaces(char* string);

//Returns the size of an array of strings
int returnStringArraySize(char** string);

//Verifies the login command
int checkLoginCommand(char** string,int i);

//Verifies the register command
int checkRegisterCommand(char** string,int i);

//Verifies the exit and users command 
int checkExitUsersCommand(char** string, int i, int loggin);

//Parses the message send by the user(verifies if it is public and it's format) 
void parseMessage(char* string);

//Modifies a string by removing his end of line character as a message cannot have a end of line
void removeNewLine(char* string);

/* TODO add UI calls interact with user on stdin/stdout */

#endif /* defined(_UI_H_) */
