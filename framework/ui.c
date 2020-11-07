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

  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);

  /* TODO initialize ui_state */
}

char **removeSpaces(char *string) {
  int i = 0;
  int n = strlen(string);
  char **token = malloc(sizeof(char *) * n);
  const char delim[4] = "  \t\n";
  token[i] = strtok(string, delim);

  while (token[i] != NULL) {
    i++;
    token[i] = strtok(NULL, delim);
  }

  return token;

}

int checkCommand(char *string, int loginStatus) {
  //TODO: exit when eof is met
  char copyString[strlen(string)];
  char **parsedString;

  strcpy(copyString, string);
  parsedString = removeSpaces(copyString);
  int i = returnStringArraySize(parsedString);

  if (loginStatus == 0) {
    if (*parsedString[0] == '/') {
      if (checkLoginCommand(parsedString, i) == 0
          && checkRegisterCommand(parsedString, i) == 0
          && checkExitUsersCommand(parsedString, i, loginStatus) == 0) {
      } else {
        return 1;
      }
    } else {
      //parseMessage(copyString); // todo temporarily while loginStatus is not fixed
      return 1;
      //printf("The / character is missing!\n");
    }
  } else {
    if (strcmp(parsedString[0], "/register") == 0 || strcmp(parsedString[0], "/login") == 0) {
      printf("You cannot login or register again as you are already logged in! \n");
    } else if (checkExitUsersCommand(parsedString, i, loginStatus) == 0) {
      if (parsedString[0][0] == '/') {
        printf("This is not a valid message!\n");
      } else {
        parseMessage(copyString);
      }
    }
  }
  return 0;
}

int returnStringArraySize(char **string) {
  int i = 0;
  while (string[i] != NULL) {
    i++;
  }
  return i;
}

int checkLoginCommand(char **string, int i) {
  if (strcmp(string[0], "/login") == 0) {
    if (strcmp(string[0], "/login") == 0 && i < 4 && i > 2) {
      return 1;
    } else {
      printf("error: Incorrect login command!\n");
    }
  }
  return 0;
}

int checkRegisterCommand(char **string, int i) {
  if (strcmp(string[0], "/register") == 0) {
    if (strcmp(string[0], "/register") == 0 && i < 4 && i > 2) {
      return 1;
    } else {
      printf("error: Incorrect register command!\n");
    }
  }
  return 0;
}

int checkExitUsersCommand(char **string, int i, int loggedin) {
  //TODO: check hot many workers are online
  if ((strcmp(string[0], "/exit") == 0) && i < 2) {
    printf("The User exited the program!\n");
    exit(0);
  } else if ((strcmp(string[0], "/users") == 0) && i < 2) {
    if (loggedin == 1) {
      return 1;
    } else {
      printf("error: user is not logged in!\n");
    }
  }
  return 0;
}

void removeNewLine(char *string) {
  if (string[strlen(string) - 1] == '\n')
    string[strlen(string) - 1] = '\0';
}

int parseMessage(char *string) {
  //TODO: Send text as broadcast/ file and write private message with th user it send
  //TODO: Extract Username of the client
  removeNewLine(string);
  if (string[0] != ' ' && string[0] != '\t'
      && string[strlen(string) - 1] != ' '
      && string[strlen(string) - 1] != ' ' &&
      string[strlen(string) - 1] != '\n') {
    if (string[0] == '@') {
      printf("%s Hey how are you? \n", string);
    } else {
      //Send text to chat as a broadcast 
      //printf("2020-11-03 18:30:00 Group9: %s \n", string);
      return 1;
    }
  } else {
    printf("error: Not a good message format!\n");
  }
  return 0;
}