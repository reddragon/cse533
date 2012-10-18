CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g -I$(HOME)/unpv13e_linux/lib
LIBS = $(HOME)/unpv13e_linux/libunp.a
OBJ = client

all: $(OBJ)

client: client.c utils.h utils.c
	$(CC) $(CFLAGS) client.c utils.c -o client $(LIBS)

clean:
	rm $(OBJ)
