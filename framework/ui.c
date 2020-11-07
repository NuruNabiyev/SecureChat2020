#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ui.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);
  //clean conversation
  state->loggedin = 0;
  state->correctInput = 0;
  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);
  state->loggedin = 0;
  state->correctInput = 0;
  

  /* TODO initialize ui_state */
}

void ui_process_command(struct ui_state *state)
{
  if (!state->loggedin) {
      ui_state_init(state);
  }
  readLine(state);
  state->correctInput = checkCommand(state);
}

void readLine(struct ui_state *state)
{
  fgets(state->text,sizeof(state->text), stdin);
}

char** removeSpaces(char* string)
{
  int i = 0;
  int n = strlen(string);
  char** token = malloc(sizeof(char*)*n);
  const char delim[4] = "  \t\n";
  token[i] = strtok(string, delim);

  while(token[i] != NULL)
  {
    i++;
    token[i] = strtok(NULL, delim);
  }
  return token;
  
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

int checkCommand(struct ui_state *state)
{
  //TODO: exit when eof is met
  char copyString[strlen(state->text)];
  char** parsedString;

  strcpy(copyString,state->text);
  parsedString = removeSpaces(copyString);
  int sizeArray = returnStringArraySize(parsedString);
  
  if(*parsedString == NULL)
  {
    if(state->loggedin == 0) printf("error: Unknown command! \n");
    else printf("error: Wrong message structure or wrong command! \n");
  }
  else
  {
    switch (stack_of_commands(parsedString[0]))
    {
      case 1:
        if (checkLoginCommand(parsedString,sizeArray, state->loggedin) == 1) {
          state->loggedin = 1;
          return 1;
        }
        return 0;
      
      case 2:
        if (checkRegisterCommand(parsedString,sizeArray, state->loggedin) == 1) {
          state->loggedin = 1;
          return 1;
        }
        return 0;
        break;
      
      case 3:
        return checkUsersCommand(parsedString, sizeArray, state->loggedin);
        break;
      
      case 4:
        checkExitCommand(parsedString, sizeArray);
        break;
      
      case 5:
        if( state->loggedin == 0) printf("error: you are not yet logged in!\n");
        else return parseMessage(state->text);
        break;
      
      default:
        printf("error: Unknown command! \n");
        break;
    }
  }
  return 0;
}


int returnStringArraySize(char** string)
{
  int i=0;
  while(string[i] != NULL)
  {
    i++;
  }
  return i;
}

int checkLoginCommand(char** string,int i,int loggedin)
{
   if(loggedin == 0)
    {  
      if(i < 4 && i > 2)
        {
          return 1;
        }
        else
        {
          printf("error: Incorect login command!\n");
          return 2;
        }
    }
    else 
      printf("error: You are already logged in! \n");
    return 0;
}

int checkRegisterCommand(char** string,int i, int loggedin)
{
   if(loggedin == 0)
    {
      if(i < 4 && i > 2)
        {
          return 1;
        }
        else
        {
          printf("error: Incorect register command!\n");
        }
    }
    else 
      printf("error: You are already registered in! \n");
    return 0;
}

int checkUsersCommand(char** string,int i , int loggedin)
{
  if(i < 2)
  {
    if(loggedin == 1)
    {
      printf("3 Users are currently logged in.\n");
      return 1;
    }
    else
    {
      printf("error: user is not logged in!\n");
    }
  }
  return 0;
}


int checkExitCommand(char** string, int i)
{
  if(i < 2)
  {
    printf("The User exited the program!\n");
    exit(0);
  }
  return 0;
}

void removeNewLine(char* string)
{
  if(string[strlen(string)-1] == '\n')
    string[strlen(string)-1] = '\0';
}

int parseMessage(char* string)
{
  //TODO: Extract Username of the client
  removeNewLine(string);
  if(string[0] != ' ' && string[0] != '\t' 
      && string[strlen(string)-1] != ' ' 
      && string[strlen(string)-1] != ' ' 
      && string[strlen(string)-1] != '\n')
  {
    if(string[0] == '@')
    {
        printf("%s %s? \n","@user",string);
        return 1;
    }
    else
    {
      printf("2020-11-03 18:30:00 Group9: %s \n",string);
      return 1;
    }
  }
  else printf("error: Not a good message format!\n");
  return 0;
}