# Makefile template for shared library



CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g -lrt -D_FILE_OFFSET_BITS=64 `gpgme-config --libs`# C flags
LDFLAGS = -shared  # linking flags
RM = rm -f  # rm command
TARGET_LIB = libsla.so # target lib

SRCS = slalib.c # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}
	sudo apt-get install libgpgme11-dev
	sudo apt-get install libssl-dev
	wget ftp://ftp.gnupg.org/gcrypt/libassuan/libassuan-2.4.3.tar.bz2
	wget ftp://ftp.gnupg.org/gcrypt/gpgme/gpgme-1.9.0.tar.bz2
	wget ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-1.27.tar.bz2
	tar -xvf gpgme-1.9.0.tar.bz2
	tar -xvf libassuan-2.4.3.tar.bz2
	tar -xvf libgpg-error-1.27.tar.bz2
	cd libgpg-error-1.27 && ./configure --prefix=/usr && make &&make install
	cd libassuan-2.4.3 && ./configure --prefix=/usr && make && make install
	cd gpgme-1.9.0 && ./configure --prefix=/usr && make && make install

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)
