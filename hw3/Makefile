CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
OBJ = utils.o

LINKFLAGS = -lpthread
INCFLAGS  = -I../unpv13e_linux/lib
LIBS      = ../unpv13e_linux/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

#all: targets

#debug: CFLAGS += -DDEBUG -g
#debug: targets

#targets: $(OBJ)

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c
clean:
	rm -f $(OBJ)
