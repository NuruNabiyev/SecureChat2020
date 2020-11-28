#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

int lookup_host_ipv4(const char *hostname, struct in_addr *addr);

int max(int x, int y);

int parse_port(const char *str, uint16_t *port_p);

char *generate_keys(char *name, int server_or_client);

EVP_PKEY *ttp_get_pubkey(char *name, int server_or_client);

int hash_password(char *orig_pwd, unsigned char *hashed_pwd, const unsigned char *dest_salt);

#endif /* defined(_UTIL_H_) */
