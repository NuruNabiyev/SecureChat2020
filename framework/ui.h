#ifndef _UI_H_
#define _UI_H_
#define MAXIUM_INPUT 1000

struct ui_state {
  /* TODO add fields to store the command arguments */
  char input[MAXIUM_INPUT];
  int loggedIn;
  char check_eof[10];

};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/**
 * @param:strcut ui_state* state
 * @description:Contains the reading and parsing methods of the UI
 * @return:It returna an integer 1 or 0. 1 for correct input and 0 for incorrect one.
 */ 
int ui_command_process(struct ui_state *state);

/**
 * @param:struct ui_state *state
 * @description: Reads the user input and checks for end of file
 * @return: -
 */ 
void readLine(struct ui_state *state);

/**
 * @param: struct ui_state *state
 * @description: Verifies if the input has the correct format
 * @return:Returns an integer 1 for succesful input and 0 for incorrect one 
 */ 
int check_command(struct ui_state *state);

/**
 * @param: char *string, char** parsed_string
 * @description:Removes Whitespaces and creates an array of strings
 * @return:-
 */ 
void removeSpaces(char *string, char** parsed_string);

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
int checkLoginCommand(char **string, int i, int loginstatus);

/**
 * @param:char **string, int i, int loginstatus
 * @description: Verifies if the login command has the correct format 
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int checkRegisterCommand(char **string, int i, int loginstatus);

/**
 * @param:int i, int loggin
 * @description: Verifies if the users command has the correct format 
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */ 
int checkUsersCommand(int i, int loggin);

/**
 * @param:char **string, int in
 * @description:Verifies if the exit command has the correct format
 * @return:Returns an integer 1 for correct and 0 for incorrect
 */
int checkExitCommand(char **string, int in, int loginStatus);

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


#endif /* defined(_UI_H_) */
