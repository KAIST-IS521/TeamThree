#pragma once
#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <aio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <regex.h>

void set_aiocb(struct aiocb *cbp, int fd, void* buffer, size_t size);
ssize_t recvMsgUntil(int sock, const char* regex,void* buf, size_t n);
int reg_check(const char* regex, void* buf);
int reg_error_number(int error);
