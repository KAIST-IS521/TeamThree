
SRCS = client.c
OBJS = $(SRCS:.c=)

.PHONY: all
all: $(OBJS)

client: client.c
	gcc -Wall -D_FILE_OFFSET_BITS=64 -o client client.c `gpgme-config --cflags --libs` -L../ -lsla

.PHONY: clean
clean:
	rm $(OBJS)
