#!/bin/bash

# Trusted Third Party

function createKeys() {
		if [ "$#" -ne 2 ]
		then
		echo "Usage: ./ttp.sh create [server/client]"
		exit
		fi

		if ! [ -d ./ttp-keys ] 
		then
		mkdir ttp-keys
		fi

		if [ "$3" == "server" ]
		then
		if ! [ -d ./serverkeys ]
		then
			mkdir serverkeys
		fi
		if ! [ -d ./clientkeys ]
		then
			mkdir clientkeys
		fi
		else
		if ! [ -d ./clientkeys/"$3" ]
		then
			cd clientkeys
			mkdir "$3"
			cd -
		fi
		fi

		if ! [ "$(ls -A ./ttp-keys)" ]
		then
		openssl genrsa -out ./ttp-keys/ca-key.pem
		openssl req -new -x509 \
			 -key ./ttp-keys/ca-key.pem \
			 -out ./ttp-keys/ca-cert.pem \
			 -nodes -subj '/CN=ca\.sp-group9\.com/'
		cp ./ttp-keys/ca-cert.pem ./clientkeys/ca-cert.pem
		fi

		if [ "$3" == "server" ]
		then
		 	openssl genrsa -out ./serverkeys/privkey-server.pem
		openssl req -new \
			 -key ./serverkeys/privkey-server.pem \
			 -out ./ttp-keys/server-csr.pem \
			 -nodes -subj '/CN=ca\.sp-group9\.com/'
		openssl x509 -req -CA ./ttp-keys/ca-cert.pem \
			 -CAkey ./ttp-keys/ca-key.pem -CAcreateserial \
			 -in ./ttp-keys/server-csr.pem \
			 -out ./serverkeys/server-ca-cert.pem
		openssl rsa -pubout \
			 -in ./serverkeys/privkey-server.pem \
			 -out ./serverkeys/pubkey-server.pem
		else
		openssl genrsa -out ./clientkeys/"$3"/privkey-client"$3".pem
		openssl req -new -key ./clientkeys/"$3"/privkey-client"$3".pem \
			 -out ./ttp-keys/client"$3"-csr.pem \
			 -nodes \
			 -subj "/CN=client\.$3-example\.com/"
		openssl x509 -req -CA ./ttp-keys/ca-cert.pem \
			 -CAkey ./ttp-keys/ca-key.pem -CAcreateserial \
			 -in ./ttp-keys/client"$3"-csr.pem \
			 -out ./clientkeys/"$3"/client"$3"-ca-cert.pem
		openssl rsa -pubout \
			 -in ./clientkeys/"$3"/privkey-client"$3".pem \
			 -out ./clientkeys/"$3"/pubkey-client"$3".pem
		fi

		rm -f ./ttp-keys/server-csr.pem
}

function verifyKeys() {

	if [ "$#" -ne 2 ]
	then
		echo "Usage: ./ttp.sh verify [client]"
		exit
	fi

	if [ "$2" == "server" ]
	then
		echo "`pwd`/serverkeys/pubkey-server.pem"
		return 
	else [ -e ./clientkeys/"$2"/pubkey-client"$2".pem ]
		echo "`pwd`/clientkeys/"$2"/pubkey-client"$2".pem"
		return
	fi
	echo "Key not found in directory!"
}

END_PATH=""

if [ "$1" == "create" ]
then
	createKeys $1 $2
fi

if [ "$1" == "verify" ]
then
	verifyKeys $1 $2
fi

