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
    char *current_user;
    /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  // todo only broadcasting implemented for now
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "SELECT message FROM global_chat ORDER by id DESC LIMIT 1;";
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
 * Inserts global message to db
 * @return 1 if failed, 0 if all ok
 */
static int insert_global(struct worker_state *state,
                         const struct api_msg *msg) {
  char *curr_time = get_current_time();
  char *user = "group 9:";  //todo extract from db
  char *main_msg = (char *) malloc(strlen(msg->received) + strlen(curr_time) + strlen(user));
  sprintf(main_msg, "%s %s %s\n", curr_time, user, msg->received);

  db_rc = sqlite3_open(DB_NAME, &db);
  if (db_rc != SQLITE_OK) {
    puts("Could not open database");
    return 1;
  }

  // SQL Query vulnerable to SQL Injection, will fix with parameterised query
  // using sqlite3_bind_text() in coming deadline.
  char *sql_format = "INSERT INTO global_chat (message) VALUES (\"%s\");";
  db_sql = (char *) malloc(strlen(sql_format) + strlen(main_msg));
  sprintf(db_sql, sql_format, main_msg);
  sqlite3_prepare_v2(db, db_sql, (int) strlen(db_sql), &db_stmt, NULL);
  db_rc = sqlite3_step(db_stmt);
  sqlite3_finalize(db_stmt);
  if (db_rc == SQLITE_DONE) {
    free(main_msg);
    notify_workers(state);
  } else {
    printf("ERROR in adding message to table: %s\n", sqlite3_errmsg(db));
  }

  return 0;
}

/**
 * Query all messages and send to that client
 * @return 0 on success
 */
static int send_all_messages(struct worker_state *state) {
  db_rc = sqlite3_open(DB_NAME, &db);
  char *db_sql = "SELECT message FROM global_chat;";
  sqlite3_prepare_v2(db, db_sql, strlen(db_sql), &db_stmt, NULL);

  // todo gather to single payload and send?
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    unsigned const char *curr_msg = sqlite3_column_text(db_stmt, 0);
    send(state->api.fd, curr_msg, strlen(curr_msg), 0);
  }
  sqlite3_finalize(db_stmt);
  return 0;
}

/**
 * Extracts username from /login and /register commands
 * @param payload full login or register message from client
 * @return username
 */
static char *extract_username(char *payload) {
  int first_space_found = 0;
  char *username = (char *) malloc(sizeof(char *) * 256);
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
  printf("username %s.\n", username);
  return username;
}

static char *extract_password(char *payload) {
  int spaces_found = 0;
  char *password = (char *) malloc(sizeof(char *) * 256);
  for (int i = 0; i < strlen(payload) - 1; ++i) { // without newline
    if (spaces_found == 2) {
      strncat(password, &(payload[i]), 1);
    }

    if (payload[i] == ' ') {
      ++spaces_found;
    }
  }
  char null = '\0';
  strncat(password, &null, 1);
  printf("password %s.\n", password);
  return password;
}

static int set_logged_in(struct worker_state *state) {
  db_rc = sqlite3_open(DB_NAME, &db);
  db_sql = "UPDATE users set is_logged_in = ?1 where username = ?2;";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_int(db_stmt, 1, 1);
  sqlite3_bind_text(db_stmt, 2, state->current_user, -1, SQLITE_STATIC);
  db_rc = sqlite3_step(db_stmt);

  if (db_rc != SQLITE_DONE) {
    printf("ERROR updating data: %s\n", sqlite3_errmsg(db));
    return -1;
  }
  sqlite3_finalize(db_stmt);
  return 1;
}

/**
 * Adds user into DB
 * @return 1 on success, 0 if error
 */
static void create_user(struct worker_state *state, char *reg_payload) {
  char *username = extract_username(reg_payload);
  char *password = extract_password(reg_payload); // todo hash and salt this
  db_rc = sqlite3_open(DB_NAME, &db);

  db_sql = "SELECT COUNT(*) FROM users WHERE username = ?1";
  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int user_exists = 0;
  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW) {
    user_exists = sqlite3_column_int(db_stmt, 0);
  }
  sqlite3_finalize(db_stmt);

  if (user_exists == 0) {
    // add user to table
    db_sql = "INSERT INTO users (username, hash_pwd, is_logged_in) "
             "VALUES (?1, ?2, ?3);";
    sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
    sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(db_stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_int(db_stmt, 3, 1);  // make user online
    db_rc = sqlite3_step(db_stmt);
    sqlite3_finalize(db_stmt);
    if (db_rc == SQLITE_DONE) {
      state->current_user = username;
      // send to client
      char *register_ok = "You have been registered!";
      send(state->api.fd, register_ok, strlen(register_ok), 0);
      send_all_messages(state);
    } else {
      printf("ERROR inserting data: %s\n", sqlite3_errmsg(db));
      char *registration_fail = "error: please try again\n";
      send(state->api.fd, registration_fail, strlen(registration_fail), 0);
    }

  } else {
    // send to client
    char *registration_fail = "error: user already exists\n";
    send(state->api.fd, registration_fail, strlen(registration_fail), 0);
  }
}

static void check_login(struct worker_state *state, char *reg_payload) {
  printf("check_login begin\n");

  char *username = extract_username(reg_payload);
  char *password = extract_password(reg_payload);
  printf("extracted %s.%s.\n", username, password);
  free(username);
  free(password);

//  db_rc = sqlite3_open(DB_NAME, &db);
//  db_sql = "SELECT * FROM users WHERE username = ?1";
//  sqlite3_prepare_v2(db, db_sql, -1, &db_stmt, NULL);
//  sqlite3_bind_text(db_stmt, 1, username, -1, SQLITE_STATIC);

  int password_matches = 0;
//  while ((db_rc = sqlite3_step(db_stmt)) == SQLITE_ROW)
//    if (strcmp(password, sqlite3_column_text(db_stmt, 2)) == 0)
//      password_matches = 1;
//  sqlite3_finalize(db_stmt);

  if (password_matches == 1) {
    printf("password_matches\n");
    int ret = set_logged_in(state);

    if (ret == -1) {
      printf("ERROR updating login info: %s\n", sqlite3_errmsg(db));
    } else {
      printf("user logged in!\n");
//      char *text = "You have been logged in!";
//      send(state->api.fd, text, strlen(text), 0);
//      // save user in global variable
//      state->current_user = username;
      // send all past messages to user
      //send_all_messages(state);
    }
  } else {
    // send error to client
//    char *login_fail = "error: invalid credentials\n";
//    send(state->api.fd, login_fail, strlen(login_fail), 0);
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
    create_user(state, msg->received);
    set_logged_in(state);
  } else if (strstr(msg->received, "/login") != NULL) {
    check_login(state, msg->received);
  } else if (strcmp(msg->received, "/users\n") == 0) {
    printf("users asked\n");
  } else {
    // add to db and ask every worker to broadcast
    return insert_global(state, msg);
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
