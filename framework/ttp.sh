#!/bin/bash

# Trusted Third Party

function createKeys() {
		if [ "$#" -ne 1 ]
		then
		echo "Usage: ./ttp.sh create [server/client]"
		exit
		fi

		echo "$(date): Creating keys for $1." >> ttp.log

		if ! [ -d ./ttp-keys ] 
		then
		mkdir ttp-keys
		fi

		if [ "$1" == "server" ]
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
		if ! [ -d ./clientkeys/"$1" ]
		then
			cd clientkeys || exit
			mkdir "$1"
			cd - || exit
		fi
		fi

		if ! [ "$(ls -A ./ttp-keys)" ]
		then
			openssl genrsa -out ./ttp-keys/ca-key.pem >/dev/null
			openssl req -new -x509 \
				 -key ./ttp-keys/ca-key.pem \
				 -out ./ttp-keys/ca-cert.pem \
				 -nodes -subj '/CN=ca\.sp-group9\.com/' \
				 >/dev/null
			cp ./ttp-keys/ca-cert.pem ./clientkeys/ca-cert.pem
		fi

		if [ "$1" == "server" ]
		then
		 	openssl genrsa -out ./serverkeys/privkey-server.pem >/dev/null
			openssl req -new \
				 -key ./serverkeys/privkey-server.pem \
				 -out ./ttp-keys/server-csr.pem \
				 -nodes -subj '/CN=ca\.sp-group9\.com/' >/dev/null
			openssl x509 -req -CA ./ttp-keys/ca-cert.pem \
				 -CAkey ./ttp-keys/ca-key.pem -CAcreateserial \
				 -in ./ttp-keys/server-csr.pem \
				 -out ./serverkeys/server-ca-cert.pem >/dev/null
			openssl rsa -pubout \
				 -in ./serverkeys/privkey-server.pem \
				 -out ./serverkeys/pubkey-server.pem >/dev/null
				 echo "$(pwd)/serverkeys"
		else
			openssl genrsa -out ./clientkeys/"$1"/privkey-client"$1".pem >/dev/null
			openssl req -new -key ./clientkeys/"$1"/privkey-client"$1".pem \
				 -out ./ttp-keys/client"$1"-csr.pem \
				 -nodes \
				 -subj "/CN=client\.$1-example\.com/" >/dev/null
			openssl x509 -req -CA ./ttp-keys/ca-cert.pem \
				 -CAkey ./ttp-keys/ca-key.pem -CAcreateserial \
				 -in ./ttp-keys/client"$1"-csr.pem \
				 -out ./clientkeys/"$1"/client"$1"-ca-cert.pem >/dev/null
			openssl rsa -pubout \
				 -in ./clientkeys/"$1"/privkey-client"$1".pem \
				 -out ./clientkeys/"$1"/pubkey-client"$1".pem >/dev/null

				 echo "$(pwd)/clientkeys/$1"
		fi

		rm -f ./ttp-keys/server-csr.pem
}

function verifyKeys() {

	if [ "$#" -ne 2 ]
	then
		echo "Usage: ./ttp.sh verify [client]"
		exit
	fi

	echo "$(date): Verifying keys for $2." >> ttp.log

	if [ "$2" == "server" ]
	then
		cat ./serverkeys/server-ca-cert.pem
		#openssl x509 -in ./serverkeys/server-ca-cert.pem -text -noout
		return 
	else [ -e ./clientkeys/"$2"/pubkey-client"$2".pem ]
		cat ./clientkeys/"$2"/client"$2"-ca-cert.pem
		#openssl x509 -in ./clientkeys/$2/client$2-ca-cert.pem -text -noout
		return
	fi
	echo "Key not found in directory!"
}

if [ ! -e ./ttp.log ]
then
	touch ./ttp.log
fi

if [ "$1" == "create" ]
then
	createKeys "$2"
fi

if [ "$1" == "verify" ]
then
	verifyKeys "$1" "$2"
fi

