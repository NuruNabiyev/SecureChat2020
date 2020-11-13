#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {

  assert(state);
  assert(msg);

  char client_msg[500];
  int recv_bytes = recv(state->fd, client_msg, 500, 0);
  // substring until received bytes
  char substr[recv_bytes];
  for (int i = 0; i < recv_bytes; ++i)
    substr[i] = client_msg[i];
  substr[recv_bytes] = '\0';

  //printf("api_recv: %i bytes from %i: %s\n", recv_bytes, state->fd, substr);

  msg->received = (char *) malloc(sizeof(char *) * recv_bytes);
  strcpy(msg->received, substr);

  if (recv_bytes > 0) return 1;
  else if (recv_bytes < 0) return -1;
  else return 0;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);
  //free(msg->received);
  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

  assert(state);

  /* TODO clean up API state */
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  /* TODO initialize API state */
}
