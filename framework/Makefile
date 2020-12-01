.PHONY: all clean

CFLAGS=-g -fno-stack-protector -z execstack
LDLIBS=-lsqlite3 -lcrypto -lssl -lcrypto

all: client.c server.c ttp
	gcc -o client client.c ssl-nonblock.c api.c ui.c util.c $(LDLIBS) $(CFLAGS)
	gcc -o server server.c worker.c ssl-nonblock.c api.c util.c chatdb.c $(LDLIBS) $(CFLAGS)

clean:
	rm -rf server client *.o chat.db clientkeys serverkeys ttp-keys ttp.log

ttp:
	./ttp.sh create server > /dev/null 2>&1