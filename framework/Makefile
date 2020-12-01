.PHONY: all clean

#CFLAGS=-g -Wall -Werror -UDEBUG
#CFLAGS=-g -Wall -UDEBUG
CFLAGS=-g -fno-stack-protector -z execstack
LDLIBS=-lsqlite3 -lcrypto -lssl -lcrypto

all: ttp client.c server.c
	gcc -o client client.c ssl-nonblock.c api.c ui.c util.c $(LDLIBS) $(CFLAGS)
	gcc -o server server.c worker.c ssl-nonblock.c api.c util.c chatdb.c $(LDLIBS) $(CFLAGS)
	
#all: client server

clean:
	rm -rf server client *.o chat.db clientkeys serverkeys ttp-keys ttp.log

ttp:
	./ttp.sh create server

#ui.o: ui.c ui.h
#
#client.o: client.c api.h ui.h util.h ssl-nonblock.c ssl-nonblock.h
#
#api.o: api.c api.h ssl-nonblock.c ssl-nonblock.h
#
#server.o: server.c util.h ssl-nonblock.c ssl-nonblock.h
#
#util.o: util.c util.h
#
#worker.o: worker.c util.h worker.h chatdb.c chatdb.h ssl-nonblock.c ssl-nonblock.h
#
#chatdb.o: chatdb.c chatdb.h ssl-nonblock.c ssl-nonblock.h
#
#myssl.o: ssl-nonblock.c ssl-nonblock.h
#
#client: myssl.o client.o api.o ui.o util.o
#
#server: myssl.o server.o api.o util.o worker.o chatdb.o