#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "chatdb.h"
#include "ssl-nonblock.h"

struct worker_state {
    struct api_state api;
    int eof;
    int server_fd;  /* server <-> worker bidirectional notification channel */
    int server_eof;
    char *current_user;
    char *last_notified_msg; // same message should not be replied again
    /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  // retrieve last message for this user, send to him if it is not as the last one
  const char *last_msg = retrieve_last(state->current_user);
  if (last_msg == NULL) return 0;
  if (state->last_notified_msg == NULL
      || strcmp(last_msg, state->last_notified_msg) != 0) {
    ssl_block_write(ssl, state->api.fd, last_msg, strlen(last_msg));
    state->last_notified_msg = malloc(strlen(last_msg));
    sprintf(state->last_notified_msg, "%s", last_msg);
  }
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state) {
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

/**
 * Extracts username from /login and /register commands
 * @param payload full login or register message from client
 * @return username
 */
static char *extract_username(char *payload) {
  int first_space_found = 0;
  char username[500] = "";
  for (int i = 0; i < strlen(payload); ++i) {
    if (first_space_found == 1) {
      strncat(username, &(payload[i]), 1);
      if (payload[i + 1] == ' ') {
        char null = '\0';
        strncat(username, &null, 1);
        break;
      }
    }

    if (payload[i] == ' ') {
      if (first_space_found == 0) {
        first_space_found = 1;
      }
    }
  }

  char *usrPtr = (char *) malloc(sizeof(char *) * 500);
  strncpy(usrPtr, username, strlen(username) + 1);
  return usrPtr;
}

static char *extract_password(char *payload) {
  int spaces_found = 0;
  char password[500] = "";
  for (int i = 0; i < strlen(payload); ++i) { // without newline
    if (spaces_found == 2) {
      strncat(password, &(payload[i]), 1);
    }

    if (payload[i] == ' ') {
      ++spaces_found;
    }
  }
  char null = '\0';
  strncat(password, &null, 1);

  char *pwdPtr = (char *) malloc(sizeof(char *) * 500);
  strncpy(pwdPtr, password, strlen(password) + 1);
  return pwdPtr;
}

/**
 * Extracts user from @user message
 * @param private_msg full message from network
 * @return username without @
 */
static char *extract_user_from_priv(char *private_msg) {
  char username[500] = "";
  for (int i = 0; i < strlen(private_msg); ++i) {
    if (private_msg[i] == '@') continue;
    if (private_msg[i] == ' ') break;
    strncat(username, &(private_msg[i]), 1);
  }
  char null = '\0';
  strncat(username, &null, 1);
  char *usrPtr = (char *) malloc(sizeof(char *) * 500);
  strncpy(usrPtr, username, strlen(username) + 1);
  return usrPtr;
}

/**
 * Singe most of the code for login and register is same, except for db
 * @param is_register_or_login  1 for register, 0, for login
 * @param state of the worker
 * @param received full message from user
 * @return 0 in case of a problem
 */
static int execute_credentials(int is_register_or_login, struct worker_state *state, char *received) {
  if (state->current_user != NULL) {
    char err[] = "You are already logged in\n";
    ssl_block_write(ssl, state->api.fd, err, strlen(err));
    return 0;
  }

  char *username = extract_username(received);
  char *password = extract_password(received); // todo hash and salt this
  int ret = -1;
  if (is_register_or_login == 1) {
    ret = create_user(username, password, state->api.fd, ssl);
  } else if (is_register_or_login == 0) {
    ret = check_login(username, password, state->api.fd, ssl);
  }
  if (ret == 1) {
    state->current_user = username;
    set_logged_in(state->current_user);
    // need to initialize last sent message
    char *last_msg = send_all_messages(state->api.fd, state->current_user, ssl);
    state->last_notified_msg = malloc(strlen(last_msg));
    sprintf(state->last_notified_msg, "%s", last_msg);
  }
}

static int execute_users(struct worker_state *state) {
  if (state->current_user == NULL) {
    char err[] = "You must login first\n";
    ssl_block_write(ssl,state->api.fd, err, strlen(err));
    return 0;
  }
  char *users = retrieve_all_users();
  ssl_block_write(ssl,state->api.fd, users, strlen(users));
  return 1;
}

/**
 * @return 0 in case of problem
 */
static int execute_private(struct worker_state *state, char *received) {
  if (state->current_user == NULL) {
    char err[] = "You must login first\n";
    ssl_block_write(ssl,state->api.fd, err, strlen(err));
    return 0;
  }

  char *other_user = extract_user_from_priv(received);
  int other_user_exists = user_exists(other_user);
  if (other_user_exists) {
    int rc = process_private(received, other_user, state->current_user);
    if (rc == 1) {
      // notify us and recipient to extract last message (this one) and send
      notify_workers(state);
    } else {
      char err[] = "Error occurred, please retry\n";
      ssl_block_write(ssl,state->api.fd, err, strlen(err));
    }
  } else {
    char err[] = "Recipient is not found\n";
    ssl_block_write(ssl,state->api.fd, err, strlen(err));
  }
  return 1;
}

/**
 * @return 0 in case of problem
 */
static int execute_public(struct worker_state *state, char *received) {
  if (state->current_user == NULL) {
    char err[] = "You must login first\n";
    ssl_block_write(ssl,state->api.fd, err, strlen(err));
    return 0;
  }

  // add to db and ask every worker to broadcast
  int inserted = process_global(received, state->current_user);
  if (inserted == 1) {
    notify_workers(state);
  }
  return 1;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *msg) {
  int check_input = 0;
  check_input = worker_check_command(msg->received);
  if (check_input == 2) {
    execute_credentials(1, state, msg->received);
  } else if (check_input == 1) {
    execute_credentials(0, state, msg->received);
  } else if (check_input == 3) {
    execute_users(state);
  } else if (msg->received[0] == '@' && check_input == 5) {
    execute_private(state, msg->received);
  } else if (check_input == 5) {
    execute_public(state, msg->received);
  }

  return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg, ssl);
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

static int handle_s2w_read(struct worker_state *state) {
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(ssl)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(struct worker_state *state, int connfd, int server_fd) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  /* TODO any additional worker state initialization */

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(struct worker_state *state) {
  logout_user(state->current_user);

  /* clean up API state */
  api_state_free(&state->api);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn))
void worker_start(int connfd, int server_fd) {
  struct worker_state state;
  int success = 1;

  ctx = SSL_CTX_new(TLS_server_method());
  ssl = SSL_new(ctx);
  int ret = SSL_use_certificate_file(ssl, "serverkeys/server-ca-cert.pem", SSL_FILETYPE_PEM);
  if (ret < 1)
    puts("error: SSL_use_certificate_file");
  ret =  SSL_use_PrivateKey_file(ssl, "serverkeys/privkey-server.pem", SSL_FILETYPE_PEM);
  if (ret < 1)
    puts("error: SSL_use_PrivateKey_file");

  /* set up SSL connection with client */
  set_nonblock(connfd);
  SSL_set_fd(ssl, connfd);
  ssl_block_accept(ssl, connfd);

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0) {
    goto cleanup;
  }
  /* TODO any additional worker initialization */

  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

  cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}

int worker_check_command(char *message) {

  char **parsedStrings;
  char *copyStrings = malloc(strlen(message) + 2);

  strcpy(copyStrings, message);
  parsedStrings = removeSpaces(copyStrings);
  int arraySize = returnStringArraySize(parsedStrings);


  if (parsedStrings[0] == NULL || strcmp(message, "\n") == 0) {
    printf("error:Empty text is not permitted.\n");
    return 0;
  }

  switch (stack_of_commands(parsedStrings[0])) {
    case 1:
      return worker_checkLoginCommand(parsedStrings, arraySize);
    case 2:
      return worker_checkRegisterCommand(parsedStrings, arraySize);
    case 3:
      return worker_checkUsersCommand(arraySize);
    case 4:
      return checkExitCommand(parsedStrings, arraySize);
    case 5:
      // if (!state->loggedIn) printf("Error: you are not logged in.\n");
      return parseMessage(message);
      break;
    default:
      printf("Error: unknown command.\n");
      break;
  }
  free(parsedStrings);
  free(copyStrings);

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

int worker_checkUsersCommand(int i) {
  if (i < 2) {
    return 3;
  }
  return 0;
}


int worker_checkLoginCommand(char **string, int i) {
  if (i < 4 && i > 2) return 1;
  else printf("error: Incorrect login command!\n");
  return 0;
}

int worker_checkRegisterCommand(char **string, int i) {
  if (i < 4 && i > 2) return 2;
  else printf("error: Incorrect register command!\n");

  return 0;
}

int checkExitCommand(char **string, int i) {

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
  // removeNewLine(string);

  if (string[0] != ' ' && string[0] != '\t'
      && string[strlen(string) - 1] != ' ' &&
      string[strlen(string) - 1] != '\t') {

    if (string[0] == '@') { return 5; }
    else { return 5; }
  } else {
    printf("error: Not a good message format!\n");
  }
  return 0;
}