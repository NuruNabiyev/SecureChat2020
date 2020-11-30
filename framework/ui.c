#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

#define MAX_INPUT 1000

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

int ui_command_process(struct ui_state *state) {
  readLine(state);
  if(strcmp(state->check_eof, "secProg") != 0)
    return check_command(state);
  else
  {
    return 0;
  }
}

void readLine(struct ui_state *state){
  strcpy(state->check_eof,"test");
  if(fgets(state->input, MAX_INPUT,stdin) == NULL)
  {
    strcpy(state->check_eof, "secProg");
  }
  if(state->check_eof != NULL)
  {
    size_t ln = strlen(state->input) - 1;
    if (state->input[ln] == '\n'){
      state->input[ln] = '\0';
      }
    
  }
}

int check_command(struct ui_state *state) {

  if(strlen(state->input) <= 200)
  {
    char *parsedString[310] = {" "};
    char copyString[strlen(state->input) + 2];
    int count_characters = 0;


    strcpy(copyString, state->input);
    removeSpaces(copyString, parsedString);

    if (parsedString[0] == NULL || strcmp(state->input, "\n") == 0) {
      printf("error: invalid command format\n");
      return 0;
    }

    int arraySize = returnStringArraySize(parsedString);
    char message[300] = "asd";

    for(int i=0; i<= arraySize-1;i++)
    {
      count_characters = count_characters + strlen(parsedString[i]);
      if(count_characters > 200)
      {
        printf("error: The input excited the limit of 200 characters");
        return 0;
      }
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
        if (state->loggedIn == 0) 
        {
          printf("error: command not currently available\n");
          return 0;
        }else if (state->loggedIn == 1) 
        {
          char formated_message[310] = "ad";
          char full_message[310] = "ad";
          strcpy(full_message, parsedString[0]);
          int i = 1;
          if(arraySize > 1)
          {
            while(i < arraySize)
            {
              sprintf(formated_message, " %s",parsedString[i]);
              strcat(full_message,formated_message);
              i++;
            }
            // printf("%s \n",full_message);
          }
          else
          {
            if(parseMessage(full_message) == 1)
            {
              return 1;
            }
          }
          
           if(parseMessage(full_message) == 1)
           {
             strcpy(state->input, full_message);
             return 1;
           }
           else return 0;
           
        }
        else 
        {
          state->loggedIn = 0;
          printf("error: command not currently available\n");
          return 0;
        }
        break;
      default:
        printf("error: unknown command %s\n",parsedString[0]);
        break;
    }
    return 0;
  }
  else
  {
    printf("error: User input cannot be larger than 200 characters! \n");
    return 0;
  }
  

    return 0;
}

int stack_of_commands(char *string) {
  if (strcmp(string, "/login") == 0) return 1;
  if (strcmp(string, "/register") == 0) return 2;
  if (strcmp(string, "/users") == 0) return 3;
  if (strcmp(string, "/exit") == 0) return 4;
  if (string[0] != '/') return 5;
  return 0;
}

void removeSpaces(char *string, char** parsed_string) {
  int i = 0;
  int n = strlen(string) + 2;
  const char delim[4] = "  \t";
  parsed_string[i] = strtok(string, delim);

  while (parsed_string[i] != NULL) {
    i++;
    parsed_string[i] = strtok(NULL, delim);
  }
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
    printf("error: command not currently available\n");
    return 0;
  }
  if (i < 2) {
    return 1;
  }
  else
  {
     printf("error: invalid command format\n");
  }
  
  return 0;
}


int checkLoginCommand(char **string, int i, int loggedIn) {
  
  if (loggedIn) {
    printf("error: command not currently available\n");
    return 0;
  }
  if (i < 4 && i > 2) 
  {
    if(verify_username(string[1]) == 1)
    {
      if(verify_password(string[2]) == 1) return 1;
      else printf("error: Please insert a password between 8 to 15 alphanumeric & allowed special characters!\n");
    }
    else printf("error: Please insert a username with max 32 alphanumeric and allowed special characters!\n");
  }
  else printf("error: invalid command format\n");
  return 0;
}

int checkRegisterCommand(char **string, int i, int loggedIn) {
  
  if (loggedIn) {
    printf("error: command not currently available\n");
    return 0;
  }
  if (i < 4 && i > 2) 
  {
    if(verify_username(string[1]) == 1)
    {
      if(verify_password(string[2]) == 1) return 1;
      else printf("error: Please insert a password between 8 to 15 alphanumeric & special characters!\n");
    }
    else printf("error: Please insert a username with max 32 alphanumeric and allowed special characters!\n");
  }
  else printf("error: invalid command format\n");

  return 0;
}

int checkExitCommand(char **string, int i, int loggedin) {

  if (i < 2) {
    printf("The User exited the program!\n");
    exit(0);
  }
  else
  {
    printf("error: invalid command format\n");
  }
  
  return 0;
}


int parseMessage(char *string) {
  if(verify_message(string) == 1)
  {
      return 1;
  }
  else
  {
    printf("error: Non-Ascii characters are not accepted! \n");
  }
  
  return 0;
}


int verify_password(char* string)
{
  regex_t regex;
  int first_check = 0;
  first_check = regcomp(&regex,"[a-zA-Z0-9@$!%*?^&]\\{1,\\}", 0);
  if (first_check != 0) 
  {
    printf("Regex did not complie correctly \n");
  }
  first_check = regexec(&regex, string , 0,NULL,0);
  
  if(first_check == 0 && strlen(string) < 15) return 1;
  else return 0;
  
  return 0;
}

int verify_username(char* string)
{
  regex_t regex;
  int first_check = 0;
  first_check = regcomp(&regex,"[a-zA-Z0-9@$!%*?^&]\\{1,\\}", 0);
  if (first_check != 0) 
  {
    printf("Regex did not complie correctly \n");
  }
  first_check = regexec(&regex, string , 0,NULL,0);
  
  if(first_check == 0 && strlen(string) < 33)return 1;
  else return 0;
  
  return 0;
}

int verify_message(char* string)
{
  regex_t regex;
  int first_check = 0;
  first_check = regcomp(&regex,"[a-zA-Z]", 0);
  if (first_check != 0) 
  {
    printf("Regex did not complie correctly \n");
  }
  first_check = regexec(&regex, string , 0,NULL,0);
  
  if(first_check == 0)return 1;
  else return 0;
  
  return 0;
}