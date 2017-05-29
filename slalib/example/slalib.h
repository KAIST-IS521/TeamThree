#pragma once
#include <sys/socket.h>

enum SockType {TCP, UDP};

struct Sock
{
    enum SockType type;
    struct sockaddr_in *addr;
};

//SLA Functions
ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n);
int sendMsg(int sock, const char* buf, size_t n);
int handshake(int sock, const char* ID,
              const char* privKeyPath,
              const char* passPath,
              const char* successMsg);
void closeSock(int sock);
int openUDPSock(char *IP, unsigned short port);
int openTCPSock(char *IP, unsigned short port);
char* readFile(const char* filename, size_t* len);
