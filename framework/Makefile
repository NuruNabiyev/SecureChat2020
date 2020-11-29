.PHONY: all clean

#CFLAGS=-g -Wall -Werror -UDEBUG
#CFLAGS=-g -Wall -UDEBUG
CFLAGS=-g
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server ttp

clean:
	rm -rf server client *.o chat.db clientkeys serverkeys ttp-keys ttp.log

ttp:
	./ttp.sh create server

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h

api.o: api.c api.h 

server.o: server.c util.h

util.o: util.c util.h

worker.o: worker.c util.h worker.h chatdb.c chatdb.h

chatdb.o: chatdb.c chatdb.h

client: client.o api.o ui.o util.o

server: server.o api.o util.o worker.o chatdb.o



