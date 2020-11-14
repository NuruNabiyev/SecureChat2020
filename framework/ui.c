#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define MAX_INPUT 300
#include "ui.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);
  state->loggedIn = 0;
  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);
  state->loggedIn = 0;
  /* TODO initialize ui_state */
}

int ui_command_process(struct ui_state *state)
{
  readLine(state->input);
  return check_command(state);
}

void readLine(char* input)
{
  setvbuf(stdin, NULL, _IONBF, 0 );
  setvbuf(stdout, NULL, _IONBF, 0);
  fgets(input,MAX_INPUT,stdin);
}

int check_command(struct ui_state *state)
{ 
  // char* string = malloc(strlen(state->input)+1);
  char **parsedString;
  char* copyString = malloc(strlen(state->input)+1);

  // strcpy(string, state->input);
  strcpy(copyString, state->input);
  parsedString = removeSpaces(copyString);
  int arraySize = returnStringArraySize(parsedString);

 
  if (parsedString[0] == NULL) {
    printf("error:Empty text is not permitted.\n");
    return 0;
  }

  switch (stack_of_commands(parsedString[0])) {
    case 1:
      return checkLoginCommand(parsedString, arraySize, state->loggedIn);
    case 2: 
      return checkRegisterCommand(parsedString, arraySize, state->loggedIn);
    case 3:
      return checkUsersCommand(arraySize, state->loggedIn);
    case 4:
      return checkExitCommand(parsedString, arraySize, state->loggedIn);
    case 5:
      if (!state->loggedIn) printf("Error: you are not logged in.\n");
      else return parseMessage(state->input);
      break;
    default:
      printf("Error: unknown command.\n");
      break;
  }
  free(parsedString);
  free(copyString);

  return 0;
}

int stack_of_commands(char* string)
{
  if(strcmp(string,"/login") == 0) return 1;
  if(strcmp(string,"/register") == 0) return 2;
  if(strcmp(string,"/users") == 0) return 3;
  if(strcmp(string,"/exit") == 0) return 4;
  if(string[0] != '/') return 5; 
  return 0;
}

char **removeSpaces(char *string) {
  int i = 0;
  int n = strlen(string);
  char **token = malloc(sizeof(char *) * n);
  const char delim[4] = "  \t";
  token[i] = strtok(string, delim);

  while (token[i] != NULL) {
    i++;
    token[i] = strtok(NULL, delim);
  }

  return token;
}

int returnStringArraySize(char **string) {
  int i = 0;
  while (string[i] != NULL) {
    i++;
  }
  return i;
}

int checkUsersCommand(int i, int loggedIn) {
  if (!loggedIn) {
    printf("Error: user not logged in.\n");
    return 0;
  }
  if (i < 2) {
    return 1;
  }
  return 0;
}


int checkLoginCommand(char **string, int i, int loggedIn) {
  if (loggedIn) {
    printf("You are already logged in.\n");
    return 0;
  }
    if (i < 4 && i > 2) return 1;
    else printf("error: Incorrect login command!\n");
  return 0;
}

int checkRegisterCommand(char **string, int i, int loggedIn) {
  if(loggedIn) {
    printf("You are already logged in.\n");
    return 0;
  }
    if (i < 4 && i > 2) return 1;
    else printf("error: Incorrect register command!\n");
  
  return 0;
}

int checkExitCommand(char **string, int i, int loggedin) {

  if (i < 2) {
    printf("The User exited the program!\n");
    exit(0);
  }
  return 0;
}

void removeNewLine(char *string) {
  if (string[strlen(string) - 1] == '\n')
    string[strlen(string) - 1] = '\0';
}

int parseMessage(char *string) {
  removeNewLine(string);

  if (string[0] != ' ' && string[0] != '\t'
      && string[strlen(string)-1] != ' ' &&
      string[strlen(string)-1] != '\t') 
      {
   
      if (string[0] == '@') {return 1;}
      else{ return 1;}
      }
  else 
  {
    printf("error: Not a good message format!\n");
  }
  return 0;
}