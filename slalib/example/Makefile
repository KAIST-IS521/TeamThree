CFLAGS = -Wall -Wextra -Wno-unused-parameter -O2 -g -D_FILE_OFFSET_BITS=64
LIBPATH = -L$(LIB)
LDFLAGS = -Wl,-rpath,$(LIB)
LIB = ./
LIBS = `gpgme-config --libs` -L./ -lsla -I./

all: packages client_example

packages:
	sudo apt-get -y install libgpgme11-dev
	sudo apt-get -y install libssl-dev

client_example: client_example.c
	$(CC) -o$@ $< $(CFLAGS) $(LIBS)

clean:
	rm -f client_example

.PHONY: all clean
