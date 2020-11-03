#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "ui.h"
#include "util.h"

struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;
  /* TODO client state variables go here */
};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
  const char *hostname, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  return fd;
}


static int client_process_command(struct client_state *state) {

  assert(state);
  //TODO: Check why when using read it dumps memory 
  //TODO: see if text can be dynamically alocated or can be put in a struct

  //here the text is a varibale. maybe place it in a struct? 
  char text[500];

  // read(0,text,strlen(text));
  
  //Modify this to see how it works in both states 
  // 0 -> not loggedin; 1 -> loggedin
  state->api.loggedIn = 0;
  fgets(text,sizeof(text),stdin);
 
  checkCommand(text, state->api.loggedIn);

  /* TODO read and handle user command from stdin */
  return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
  struct client_state *state,
  const struct api_msg *msg) {

  /* TODO handle request and reply to client */

  return -1;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    state->eof = 1;
    return 0;
  }

  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* TODO if we have work queued up, this might be a good time to do it */

  /* TODO ask user for input if needed */

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds)) {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  /* TODO any additional client state initialization */

  return 0;
}

static void client_state_free(struct client_state *state) {

  /* TODO any additional client state cleanup */

  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);
}

static void usage(void) {
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv) {
  int fd;
  uint16_t port;
  struct client_state state;

  /* check arguments */
  if (argc != 3) usage();
  if (parse_port(argv[2], &port) != 0) usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0) return 1;

  /* initialize API */
  api_state_init(&state.api, fd);

  /* TODO any additional client initialization */

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);



  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}


/*##### Please leave this here for the moment####*/

// char** removeSpaces(char* string)
// {
//   int i = 0;
//   int n = strlen(string);
//   char** token = malloc(sizeof(char*)*n);
//   const char delim[4] = "  \t\n";
//   token[i] = strtok(string, delim);

//   while(token[i] != NULL)
//   {
//     i++;
//     token[i] = strtok(NULL, delim);
//   }
  
//   return token;
  
// }

// void checkCommand(char* string, int loginStatus)
// {
//   //TODO: exit when eof is met
//   char copyString[strlen(string)];
//   char** parsedString;

//   strcpy(copyString,string);
//   parsedString = removeSpaces(string);
//   int i = returnStringArraySize(parsedString);

//   if(loginStatus == 0)
//   {
//     if(*parsedString[0] == '/')
//     {
//       if(checkLoginCommand(parsedString,i) == 0 && checkRegisterCommand(parsedString,i) == 0 && checkExitUsersCommand(parsedString,i,loginStatus) == 0)
//       {
//         printf("error: Unknown Command! \n");
//       }
//     }
//     else
//     {
//       printf("The / character is missing!\n");
//     }    
//   }
//   else
//   {
//     if(strcmp(parsedString[0],"/register") == 0 || strcmp(parsedString[0],"/login") == 0)
//     {
//       printf("You cannot login or register again as you are already logged in! \n");
//     }
//     else if(checkExitUsersCommand(parsedString,i,loginStatus) == 0)
//     {
//       if(parsedString[0][0]=='/')
//       {
//         printf("This is not a valid message!\n");
//       }
//       else
//       {
//         parseMessage(copyString);
//       }
//     }
//   }
// }  
// int returnStringArraySize(char** string)
// {
//   int i=0;
//   while(string[i] != NULL)
//   {
//     i++;
//   }
//   return i;
// }

// int checkLoginCommand(char** string,int i)
// {
//   //TODO: send the message and verify auth/ received server message
//    if(strcmp(string[0],"/login") == 0)
//     {
        
//       if(strcmp(string[0],"/login") == 0 && i < 4 && i > 2)
//         {
//           printf("Send it!!\n");
//           //if(auth correct)
//           return 1;
//           //else
//           //printf("error: No such user \n")
//         }
//         else
//         {
//           printf("error: Incorect login command!\n");
//           return 2;
//         }
//     }
//     return 0;
// }

// int checkRegisterCommand(char** string,int i)
// {
//    //TODO: send the message and verify user if exists/ received server message
//    if(strcmp(string[0],"/register") == 0)
//     {
        
//       if(strcmp(string[0],"/register") == 0 && i < 4 && i > 2)
//         {
//           printf("Send it!!\n");
//           //if(registration correct)
//           return 1;
//           //else
//           //printf("error: Already registered \n")
//         }
//         else
//         {
//           printf("error: Incorect register command!\n");
//           return 2;
//         }
//     }
//     return 0;
// }

// int checkExitUsersCommand(char** string, int i, int loggedin)
// {
//   //TODO: check hot many workers are online
//   if((strcmp(string[0],"/exit") == 0) && i < 2)
//   {
//     printf("The User exited the program!\n");
//     exit(0);
//   }
//   else if( (strcmp(string[0],"/users") == 0) && i < 2)
//   {
//     if(loggedin == 1)
//     {
//     //Check how many workers are opened and which have the api_state.loggedin true
//     printf("3 Users are currently logged in.\n");
//     return 1;
//     }
//     else
//     {
//       printf("error: user is not logged in!\n");
//       return 2;
//     }
    
//   }
//   return 0;
// }

// void removeNewLine(char* string)
// {
//   if(string[strlen(string)-1] == '\n')
//     string[strlen(string)-1] = '\0';
// }

// void parseMessage(char* string)
// {
//   //TODO: Send text as broadcast/ file and write private message with th user it send
//   //TODO: Extract Username of the client
//   removeNewLine(string);
//   if(string[0] != ' ' && string[0] != '\t' && string[strlen(string)-1] != ' ' && string[strlen(string)-1] != ' ' && string[strlen(string)-1] != '\n')
//   {
//     if(string[0] == '@')
//     {
//         printf("%s Hey how are you? \n",string);
//     }
//     else
//     {
//       //Send text to chat as a broadcast 
//       printf("2020-11-03 18:30:00 Group9: %s \n",string);
//     }
//   }
//   else
//     {
//       printf("error: Not a good message format!\n");
//     }
// }


// Possible to need this code DO NOT DELETE YET


// if(*string[0] == '/')
//     {
//       if(strcmp(string[0],"/login") == 0)
//       {
        
//           if(strcmp(string[0],"/login") == 0 && i < 4 && i > 2)
//           {
//             printf("Send it!!\n");
//           }
//           else
//           {
//             printf("error: Incorect Login command!\n");
//           }
//         }
//       else if(strcmp(string[0],"/register") == 0)
//       {
//           if(strcmp(string[0],"/register") == 0 && i < 4 && i > 2)
//           {
//             printf("Send it!!\n");
//           }
//           else
//           {
//             printf("error: Incorect register command!\n");
//           }
//         }
//       else if((strcmp(string[0],"/exit") == 0) && i < 2)
//         {
//         printf("The User exited the program!\n");
//         exit(0);
//         }
//       else if( (strcmp(string[0],"/users") == 0) && i < 2)
//         {
//         //Check how many workers are opened and which have the api_state.loggedin true
//         printf("3 Users are currently logged in.\n");
//         }
//       else
//         {
//         printf("error: Unknown Command!\n");
//         }  
//     }
//     else
//     {
//       printf("error: The / character is missing!\n");
//     }
//   }
//   else
//   {
//     //take care of the messages
//     // parseMessages(string);
//     printf("parsing the message!");
//   }






// void checkCommand(char** string)
// {
//   int i = returnSize1(string);
//   if(*string[0] == '/')
//   {
//     printf("HERE: %s\n", string[0]);
//     if(strcmp(string[0],"/login") == 0)
//     {
//         printf("SIZE: %d \n", i);
//         if(strcmp(string[0],"/login") == 0 && i < 4 && i > 2)
//         {
//           // printf("%c \n",string[2][((int)strlen(string[2]))-2]);
//           printf("Papanas %s \n",string[2]);
//           // printf("Papanas %d \n",(int)strlen(string[2]));
//           if(string[2][((int)strlen(string[2]))-1] == '\n')
//           {
//             printf("it works!\n");
//           }
//           else
//           {
//             printf("Missing an argument in the login statement!\n");
//           }
          
//         }
//         else
//         {
//           printf("Incorect Login command!\n");
//         }
        
//         // else
//         // {
//         // //  registerHandle() 
//         // }
        
//     }
//     else if((strcmp(string[0],"/exit\n") == 0) || (strcmp(string[0],"/exit") == 0 && strcmp(string[1],"\n") == 0))
//     {
//       printf("The User exited the program!\n");
//       exit(0);
//     }
//     else if( (strcmp(string[0],"/users\n") == 0) || (strcmp(string[0],"/users") == 0 && strcmp(string[1],"\n") == 0))
//     {
//       //Check how many workers are opened and which have the api_state.loggedin true
//       printf("3 Users are currently logged in.\n");
//     }
//     else
//     {
//       printf("error: Unknown Command!\n");
//     }
    

//   }
//   else
//   {
//     printf("error: The / character is missing!\n");
//   }
  
// }
