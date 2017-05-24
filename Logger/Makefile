CFLAGS = -W -Wall
LIB = -lseccomp
CC = gcc
BUILDDIR = ../build

all: setup $(BUILDDIR)/logger

setup:
	sudo apt-get install libseccomp-dev

$(BUILDDIR)/logger: logger.c
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

.PHONY: all setup

