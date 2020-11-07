#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <time.h>

int lookup_host_ipv4(const char *hostname, struct in_addr *addr);

int max(int x, int y);

int parse_port(const char *str, uint16_t *port_p);

char *get_current_time(void);

#endif /* defined(_UTIL_H_) */
