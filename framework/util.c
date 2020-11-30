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

/**
 * @param:char* hostname, struct in_addr
 * @description: Looks up the host
 * @return:Returns an integer 0 for correct and -1 for incorrect
 */ 
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

/**
 * @param:char* str, uint16_t port_p
 * @description: parse a given port
 * @return:Returns an integer 0 for correct and -1 for incorrect
 */ 
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

/**
 * Extracts username from /login and /register commands
 * @param payload full login or register message from client
 * @return username
 */
char *extract_username(char *payload) {
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
  return usrPtr;
}

/**
 * @param:char* payload
 * @description: extracts password from a given payload
 * @return: Returns NULL if incorrect and pointer to password if correct
 */ 
char *extract_password(char *payload) {
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
  return pwdPtr;
}


/**
 * @param:char* name, int server_or_client
 * @description: generates keys for either client or server
 * @return: returns NULL if incorrect and char* path if correct
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

/**
 * @param:char* name, int server_or_client
 * @description: returns public key for given client or server
 * @return:returns NULL if incorrect and EVP_PKEY pubkey if correct
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

/**
 * @param:char* original password, char hashed_pwd, char salt
 * @description: hashes a given password
 * @return:returns 0 if correct and NULL if incorrect
 */ 
int hash_password(char *orig_pwd, unsigned char *hashed_pwd, const unsigned char *dest_salt) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, orig_pwd, strlen(orig_pwd) + 1);
  SHA256_Update(&ctx, dest_salt, SHA256_DIGEST_LENGTH);
  SHA256_Final(hashed_pwd, &ctx);
  return 0;
}

/**
 * @param: none
 * @description: returns the current timestamp
 * @return: returns long long timestamp
 */ 
long long current_timestamp() {
  struct timeval te;
  gettimeofday(&te, NULL);
  long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000;
  return milliseconds;
}

/**
 * @param:char* username
 * @description: retrieves private key
 * @return: returns NULL if incorrect and EVP_PKEY privkey if correct
 */ 
EVP_PKEY *get_my_private_key(char *username) {
	char file[128];
	FILE *fp;
	EVP_PKEY *privkey = EVP_PKEY_new(); 

	snprintf(file, sizeof(file), "./clientkeys/%s/privkey-client.pem", username);
	fp = fopen(file, "r");
	if (fp == NULL) {
		return NULL;
	}

	PEM_read_PrivateKey(fp, &privkey, NULL, NULL);
	fclose(fp);
	
	return privkey;
}

/**
 * @param:char* msg, EVP_PKEY pubkey
 * @description: encrypts a given message
 * @return: returns ciphertext if correct and NULL if incorrect
 */ 
char* encrypt(char* msg, EVP_PKEY * pubkey) {

	int encsize;
	RSA *rsapubkey = EVP_PKEY_get1_RSA(pubkey);
	if (rsapubkey == NULL) {
		return NULL;
	}
	int size = RSA_size(rsapubkey);
	unsigned char *encrypted = (char*)malloc(size);

	encsize = RSA_public_encrypt(size, (const unsigned char*)msg, (unsigned char*)encrypted, rsapubkey, RSA_NO_PADDING);
	if (encsize < 0) {
		return NULL;
	}

	return encrypted;
}

/**
 * @param:char* ciphertext, EVP_PKEY privkey
 * @description: decrypts given ciphertext using private key
 * @return: returns plaintext decrypted if correct NULL if incorrect
 */ 
char* decrypt(char* msg, EVP_PKEY * privkey) {

	int size;
	RSA *rsaprivkey = EVP_PKEY_get1_RSA(privkey);
	if (rsaprivkey == NULL) {
		return NULL;
	}
	int encsize = RSA_size(rsaprivkey);
	unsigned char *decrypted = (char*)malloc(size);

	size = RSA_private_decrypt(encsize, (unsigned char*)msg, (unsigned char*)decrypted, rsaprivkey, RSA_NO_PADDING);
	if (size < 0) {
		return NULL;
	}
	return decrypted;
}


