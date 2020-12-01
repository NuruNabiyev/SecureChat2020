#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sys/time.h>


/**
 * @param:char* hostname, struct in_addr
 * @description: Looks up the host
 * @return:Returns an integer 0 for correct and -1 for incorrect
 */ 
int lookup_host_ipv4(const char *hostname, struct in_addr *addr);

int max(int x, int y);


/**
 * @param:char* str, uint16_t port_p
 * @description: parse a given port
 * @return:Returns an integer 0 for correct and -1 for incorrect
 */ 
int parse_port(const char *str, uint16_t *port_p);

/**
 * @param: char *payload
 * @description:Extracts username from /login and /register commands
 * @return username
 */
char *extract_username(char *payload);

/**
 * @param:char* payload
 * @description: extracts password from a given payload
 * @return: Returns NULL if incorrect and pointer to password if correct
 */ 
char *extract_password(char *payload);

/**
 * @param:char* name, int server_or_client
 * @description: generates keys for either client or server
 * @return: returns NULL if incorrect and char* path if correct
 */ 
char *generate_keys(char *name, int server_or_client);

/**
 * @param:char* name, int server_or_client
 * @description: returns public key for given client or server
 * @return:returns NULL if incorrect and EVP_PKEY pubkey if correct
 */ 
EVP_PKEY *ttp_get_pubkey(char *name, int server_or_client);

/**
 * @param:char* original password, char hashed_pwd, char salt
 * @description: hashes a given password
 * @return:returns 0 if correct and NULL if incorrect
 */ 
EVP_PKEY *get_my_private_key();

/**
 * @param:char* msg, EVP_PKEY pubkey
 * @description: encrypts a given message
 * @return: returns ciphertext if correct and NULL if incorrect
 */ 
char* encrypt(char* msg, EVP_PKEY * pubkey);

/**
 * @param:char* ciphertext, EVP_PKEY privkey
 * @description: decrypts given ciphertext using private key
 * @return: returns plaintext decrypted if correct NULL if incorrect
 */ 
char* decrypt(char* msg, EVP_PKEY * privkey);

/**
 * @param:char* original password, char hashed_pwd, char salt
 * @description: hashes a given password
 * @return:returns 0 if correct and NULL if incorrect
 */ 
int hash_password(char *orig_pwd, unsigned char *hashed_pwd, const unsigned char *dest_salt);

/**
 * @param: none
 * @description: returns the current timestamp
 * @return: returns long long timestamp
 */ 
long long current_timestamp();

#endif /* defined(_UTIL_H_) */
