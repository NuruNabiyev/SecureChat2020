#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>

#include "api.h"
#include "util.h"
#include "worker.h"

struct worker_state {
    struct api_state api;
    int eof;
    int server_fd;  /* server <-> worker bidirectional notification channel */
    int server_eof;
    /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  // todo only broadcasting implemented for now
  db_rc = sqlite3_open("chat.db", &db);
  char *db_sql = "SELECT message FROM global_chat ORDER by id DESC LIMIT 1;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);

  // will be looped once
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    const unsigned char *last_msg = sqlite3_column_text(db_stmt, 0);
    int send_i = send(state->api.fd, last_msg, strlen(last_msg), 0);
    printf("replied %i bytes\n", send_i);
  }
  sqlite3_finalize(db_stmt);
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
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
        struct worker_state *state,
        const struct api_msg *msg) {

  char *text;

  /* TODO check properly, this is just easy way to handle login/registration/messages */
  if (strstr(msg->received, "/register") != NULL) {
    text = "You have been registered!";
  } else if (strstr(msg->received, "/login") != NULL) {
    text = "You have been logged in!";
  } else {
    printf("received global: %s\n", msg->received);

    char *curr_time = get_current_time();
    char *user = "group 9:";  //todo extract from db
    char *main_msg = (char *) malloc(strlen(msg->received) + strlen(curr_time) + strlen(user));
    sprintf(main_msg, "%s %s %s", curr_time, user, msg->received);

    // need to truncate newline
    char *newMain = (char *) malloc(strlen(main_msg) - 1);
    strncpy(newMain, main_msg, strlen(main_msg) - 1);

    db_rc = sqlite3_open("chat.db", &db);
    if (db_rc != SQLITE_OK) {
      puts("Could not open database");
      return 1;
    }

    char *sql_format = "INSERT INTO global_chat (message) VALUES (\"%s\");";
    db_sql = (char *) malloc(strlen(sql_format) + strlen(newMain) + 5);
    sprintf(db_sql, sql_format, newMain);
    sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);
    db_rc = sqlite3_step(db_stmt);
    if (db_rc == SQLITE_DONE) {
      notify_workers(state);
    } else {
      printf("ERROR in adding message to table: %s\n", sqlite3_errmsg(db));
    }

    return 0;
    // add to db and ask every worker to broadcast
  }
  int send_i = send(state->api.fd, text, strlen(text), 0);
  printf("replied %i bytes\n", send_i);

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
static int worker_state_init(
        struct worker_state *state,
        int connfd,
        int server_fd) {

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
static void worker_state_free(
        struct worker_state *state) {
  /* TODO any additional worker state cleanup */

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
void worker_start(
        int connfd,
        int server_fd) {
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
