# Makefile template for shared library

CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g -lrt -D_FILE_OFFSET_BITS=64 `gpgme-config --libs`# C flags
LDFLAGS = -shared  # linking flags
RM = rm -f  # rm command
TARGET_LIB = libsla.so # target lib
SRCS = slalib.c gpg.c # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: packages ${TARGET_LIB}

packages:
	if ! dpkg -l | grep libgpgme11-dev -c > /dev/null; then sudo apt-get install libgpgme11-dev; fi
	if ! dpkg -l | grep libssl-dev -c > /dev/nulll then sudo apt-get install libssl-dev; fi

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)
