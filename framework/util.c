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
char *generate_keys(char *name, int server_or_client) {

  FILE *fp;
  char *PATH = malloc(128); // todo Don't forget to free this after using!
  char cmd[64];

  if (server_or_client) {
    snprintf(cmd, 64, "./ttp.sh create %s >/dev/null 2>&1", name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
      return NULL;
    }
  } else {
    snprintf(cmd, 64, "./ttp.sh create server >/dev/null 2>&1");
    fp = popen(cmd, "r");
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
EVP_PKEY *ttp_get_pubkey(char *name, int server_or_client) {

  FILE *fp;
  char *CERT = malloc(2048);  // todo Don't forget to free this after using public key!
  char cmd[64];
  time_t *ptime;

  if (server_or_client) {
    snprintf(cmd, 64, "./ttp.sh verify %s", name);
  } else {
    snprintf(cmd, 64, "./ttp.sh verify server");
  }

  fp = popen(cmd, "r");
  if (fp == NULL) {
    return NULL;
  }

  X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
  if (!cert) {
    return NULL;
  }

  int i = X509_cmp_time(X509_get_notBefore(cert), ptime);
  int j = X509_cmp_time(X509_get_notAfter(cert), ptime);
  if (i != 1 || j != 1) {
    return NULL;
  }

  EVP_PKEY *pubkey = X509_get_pubkey(cert);

  return pubkey;
}

int hash_password(char *orig_pwd, unsigned char *hashed_pwd, const unsigned char *dest_salt) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, orig_pwd, strlen(orig_pwd) + 1);
  SHA256_Update(&ctx, dest_salt, SHA256_DIGEST_LENGTH);
  SHA256_Final(hashed_pwd, &ctx);
  return 0;
}
