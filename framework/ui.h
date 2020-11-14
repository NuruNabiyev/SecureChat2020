#ifndef _UI_H_
#define _UI_H_
#define MAXIUM_INPUT 500

struct ui_state {
  /* TODO add fields to store the command arguments */
  char input[MAXIUM_INPUT];
  int loggedIn;


};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/* TODO add UI calls interact with user on stdin/stdout */
int ui_command_process(struct ui_state *state);

void readLine(char* input);


int check_command(struct ui_state *state);

//Removes Whitespaces and returns a array of strings
char **removeSpaces(char *string);

//Returns the size of an array of strings
int returnStringArraySize(char **string);

//Verifies the login command
int checkLoginCommand(char **string, int i, int loginstatus);

//Verifies the register command
int checkRegisterCommand(char **string, int i, int loginstatus);

//Verifies the users command 
int checkUsersCommand(int i, int loggin);

//Verifies the exit command
int checkExitCommand(char **string, int in, int loginStatus);

//Parses the message send by the user(verifies if it is public and it's format) 
int parseMessage(char *string);

//Modifies a string by removing his end of line character as a message cannot have a end of line
void removeNewLine(char *string);

//Handles the reading and parsing of the command
void ui_process_command(struct ui_state *state);

int stack_of_commands(char* string);


#endif /* defined(_UI_H_) */
