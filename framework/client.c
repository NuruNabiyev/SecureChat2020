#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ssl-nonblock.h"
#include "api.h"
#include "ui.h"
#include "util.h"

SSL_CTX *ctx;
SSL *ssl;

struct client_state {
    struct api_state api;
    int eof;
    struct ui_state ui;
    char *my_username; // used to get my private key. Do not use to get other users' private keys
    char *last_sent_message;
    EVP_PKEY *my_priv_key;
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

/**
 * Encrypts message before sending
 * @return -1 in case of error
 */
static int send_private_msg(struct client_state *state) {
  char *other_user = extract_user_from_priv(state->ui.input);
  char *message = extract_message_from_priv(state->ui.input);
  EVP_PKEY *other_pub_key = ttp_get_pubkey(other_user, 1);
  if (other_pub_key == NULL) {
    printf("Could not get public key of %s, user might not be registered.\n", other_user);
    return -1;
  }
  char *cypher_msg = encrypt(message, other_pub_key);

  int size = strlen(other_user) + strlen(cypher_msg) + 3;
  unsigned char *send_msg = malloc(size);
  snprintf(send_msg, size,"@%s %s", other_user, cypher_msg);
  ssl_block_write(ssl, state->api.fd, send_msg, strlen(send_msg));
}

static int client_process_command(struct client_state *state) {

  assert(state);

  if (ui_command_process(&state->ui) == 1) {
    if (state->ui.input[0] == '@') {
      send_private_msg(state);
    } else {
      ssl_block_write(ssl, state->api.fd, state->ui.input, strlen(state->ui.input));
      sprintf(state->last_sent_message, "%s", state->ui.input);
    }
  }
  if (strcmp(state->ui.check_eof, "secProg") == 0) {
    state->eof = 1;
  }
  return 0;
}

/**
 * @ return 1 is this is private message, -1 otherwise
 */
static int is_private(struct client_state *state, char *msg) {
  if (strlen(msg) < (27 + strlen(state->my_username))) {
    printf("len wrong\n");
    return -1;
  }
  int maxsize = strlen(state->my_username) + 5;
  char *pattern = malloc(maxsize);
  snprintf(pattern, maxsize, ": @%s ", state->my_username);

  if (strstr(msg, pattern)) {
    return 1;
  }
  return -1;
}

static void decrypt_private(struct client_state *state, char *msg) {
  EVP_PKEY *privkey = get_my_private_key(state->my_username);
  if (privkey == NULL) {
    printf("Can't get your private key!\n");
    return;
  }
  char *encrypted = extract_cyphertext(msg, state->my_username);
  char *decrypted = decrypt(encrypted, privkey);
  printf("Decrypted %s.\n", decrypted);
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(struct client_state *state, const struct api_msg *msg) {
  if (strcmp(msg->received, "registration succeeded\n") == 0) {
    state->ui.loggedIn = 1;
    state->my_username = extract_username(state->last_sent_message);
    generate_keys(state->my_username, 1);
    state->my_priv_key = get_my_private_key(state->my_username);
    if (state->my_priv_key == NULL) {
      printf("Error: no private key found!\n");
      return 1;
    }
    printf("registration succeeded\n");
  } else if (strcmp(msg->received, "authentication succeeded\n") == 0) {
    state->ui.loggedIn = 1;
    state->my_username = extract_username(state->last_sent_message);
    state->my_priv_key = get_my_private_key(state->my_username);
    if (state->my_priv_key == NULL) {
      printf("Error: no private key found!\n");
      return 1;
    }
    printf("authentication succeeded\n");
  } else {
    if (is_private(state, msg->received) == 1) {
      decrypt_private(state, msg->received);
    } else {
      printf("%s", msg->received);
    }
  }
  return 0;
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

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }

  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(ssl)) {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  state->last_sent_message = malloc(1000);
  return 0;
}

static void client_state_free(struct client_state *state) {

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

  ctx = SSL_CTX_new(TLS_client_method());
  ssl = SSL_new(ctx);

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0) return 1;

  set_nonblock(fd);
  SSL_set_fd(ssl, fd);

  /* initialize API */
  api_state_init(&state.api, fd);

  int connection_status = ssl_block_connect(ssl, fd);
  if (connection_status == -1) {
    puts("ssl error");
    return 1;
  }

  /* TODO any additional client initialization */

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);
  /* clean up SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  return 0;
}
