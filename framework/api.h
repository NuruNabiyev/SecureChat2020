#ifndef _API_H_
#define _API_H_

#include "ssl-nonblock.h"

struct api_msg {
  char* received;
};

struct api_state {
    int fd;
};

int api_recv(struct api_state *state, struct api_msg *msg, SSL *ssl);

void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);

void api_state_init(struct api_state *state, int fd);

#endif /* defined(_API_H_) */
