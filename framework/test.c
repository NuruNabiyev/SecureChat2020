#include <stdlib.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>

EVP_PKEY *ttp_get_pubkey(char *name, int server_or_client) {

	FILE *fp;
	char *CERT = malloc(2048);	// Don't forget to free this after using public key!
	char cmd[64];

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
	EVP_PKEY *pubkey = X509_get_pubkey(cert); 
	
	return pubkey;
}


char *generate_keys(char *name, int server_or_client) {

	FILE *fp;
	char *PATH = malloc(128); // Don't forget to free this after using!
	char cmd[64];
	
	if (server_or_client) {
		snprintf(cmd, 64, "./ttp.sh create %s >/dev/null 2>&1", name);
		fp = popen(cmd, "r");
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


int main() {
	char *NAME = "12312357; ls";
	char *path;
	//path = generate_keys(NAME, 1);
	path = ttp_get_pubkey(NAME, 1);
	printf("%s", path);

	return 0;
}
