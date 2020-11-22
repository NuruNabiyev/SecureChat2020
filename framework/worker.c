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

struct worker_state {
    struct api_state api;
    int eof;
    int server_fd;  /* server <-> worker bidirectional notification channel */
    int server_eof;
    char *current_user;
    /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  // todo only broadcasting implemented for now
  broadcast_last(state->api.fd);
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
  printf("username %s.\n", usrPtr);
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
  printf("password %s.\n", pwdPtr);
  return pwdPtr;
}

/**
 * Singe most of the code for login and register is same, except for db
 * @param is_register_or_login  1 for register, 0, for login
 * @param state of the worker
 * @param received full message from user
 */
static void execute_credentials(int is_register_or_login, struct worker_state *state, char *received) {
  char *username = extract_username(received);
  char *password = extract_password(received); // todo hash and salt this
  int ret = -1;
  if (is_register_or_login == 1) {
    ret = create_user(username, password, state->api.fd);
  } else if (is_register_or_login == 0) {
    ret = check_login(username, password, state->api.fd);
  }
  if (ret == 1) {
    state->current_user = username;
    set_logged_in(state->current_user);
    send_all_messages(state->api.fd);
  }
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *msg) {
  // FIXME needle
  if (strstr(msg->received, "/register") != NULL) {
    execute_credentials(1, state, msg->received);
  } else if (strstr(msg->received, "/login") != NULL) {
    execute_credentials(0, state, msg->received);
  } else if (strcmp(msg->received, "/users") == 0) {
    char *users = retrieve_all_users();
    send(state->api.fd, users, strlen(users), 0);
  } else {
    // add to db and ask every worker to broadcast
    int inserted = insert_global(msg->received);
    if (inserted == 1) {
      notify_workers(state);
    }
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
  if (FD_ISSET(state->api.fd, &readfds)) {
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
