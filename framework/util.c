#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "util.h"

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
        host->h_addr_list &&
        host->h_addr_list[0]) {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y) {
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno) return -1;
  if (*endptr) return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535) return -1;

  *port_p = value;
  return 0;
}

/*
* server = 0
* client = 1
*/
char* generate_keys(char *name, int server_or_client) {

	FILE *fp;
	char *PATH = malloc(128); // Don't forget to free this after using!
	
	if (server_or_client) {
		fp = popen("./ttp.sh create " + *name, "r");
		if (fp == NULL) {
			return NULL;
		}
	} else {
		fp = popen("./ttp.sh create server", "r");
		if (fp == NULL) {
			return NULL;
		}
	}

	fgets(PATH, sizeof(PATH), fp);
	if (PATH == NULL) {
		return NULL;
	}
	return PATH;
}

/*
* server = 0
* client = 1
*/
char* ttp_get_pubkey(char *name, int server_or_client) {

	FILE *fp;
	char *CERT = malloc(2048);	// Don't forget to free this after using public key!

	if (server_or_client) {
		fp = popen("./ttp.sh verify" + *name, "r");
		if (fp == NULL) {
			return NULL;
		}
	} else {
		fp = popen("./ttp.sh verify server", "r");
		if (fp == NULL) {
			return NULL;
		}
	}
	fgets(CERT, sizeof(CERT), fp);
	if (CERT == NULL) {
		return NULL;
	}
	return CERT;
}

int hash_password(char *orig_pwd, unsigned char *hashed_pwd, const unsigned char *dest_salt) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, orig_pwd, strlen(orig_pwd) + 1);
  SHA256_Update(&ctx, dest_salt, SHA256_DIGEST_LENGTH);
  SHA256_Final(hashed_pwd, &ctx);
  return 0;
}


