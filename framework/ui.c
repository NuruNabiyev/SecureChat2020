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

int stack_of_commands(char *string) {
  if (strcmp(string, "/login") == 0) return 1;
  if (strcmp(string, "/register") == 0) return 2;
  if (strcmp(string, "/users") == 0) return 3;
  if (strcmp(string, "/exit") == 0) return 4;
  if (string[0] != '/') return 5;
  return 0;
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

  if (parsedString[0] == NULL) {
    printf("error: Empty messages are not allowed! \n");
  } else {
    int ret = 0;
    switch (stack_of_commands(parsedString[0])) {
      case 1:
        ret = checkLoginCommand(parsedString, i, loginStatus);
        break;

      case 2:
        ret = checkRegisterCommand(parsedString, i, loginStatus);
        break;

      case 3:
        ret = checkUsersCommand(i, loginStatus);
        break;

      case 4:
        ret = checkExitCommand(parsedString, i, loginStatus);
        break;

      case 5:
        if (!loginStatus) { printf("Error, you are not logged in.\n"); }
        else {ret = parseMessage(copyString);}
        break;

      default:
        printf("Error: unknown command.\n");
        break;
    }
    free(parsedString);
    return ret;
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

int checkUsersCommand(int i, int loggedIn) {
  if (!loggedIn) {
    printf("Error: user not logged in.\n");
    return 0;
  }

  if (i < 2) {
    printf("X users are currently logged in.\n");
    return 1;
  }
  return 0;
}

int checkLoginCommand(char **string, int i, int loggedIn) {
  if (loggedIn) {
    printf("You are already logged in.\n");
    return 0;
  }

  if (strcmp(string[0], "/login") == 0) {
    if (strcmp(string[0], "/login") == 0 && i < 4 && i > 2) {
      return 1;
    } else {
      printf("error: Incorrect login command!\n");
    }
  }
  return 0;
}

int checkRegisterCommand(char **string, int i, int loggedIn) {
  if (loggedIn) {
    printf("You are already logged in.\n");
    return 0;
  }

  if (strcmp(string[0], "/register") == 0) {
    if (strcmp(string[0], "/register") == 0 && i < 4 && i > 2) {
      return 1;
    } else {
      printf("error: Incorrect register command!\n");
    }
  }
  return 0;
}

int checkExitCommand(char **string, int i, int loggedin) {

  if ((strcmp(string[0], "/exit") == 0) && i < 2) {
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
      && string[strlen(string) - 1] != ' '
      && string[strlen(string) - 1] != '\t') {
    if (string[0] == '@') {
      printf("%s Hey how are you? \n", string);
    } else {
      //printf("2020-11-03 18:30:00 Group9: %s \n", string);
      return 1;
    }
  } else {
    printf("error: Not a good message format!\n");
  }
  return 0;
}