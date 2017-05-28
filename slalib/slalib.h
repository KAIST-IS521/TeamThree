#pragma once

enum SockType {TCP, UDP};

struct Sock
{
    enum SockType type;
    struct sockaddr_in addr;
};

ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n);
int sendMsg(int sock, const char* buf, size_t n);
int handshake(int sock, const char* ID, const char* serverFprt, const char* passphrase, const char* successMsg, int debug);
void closeSock(int sock);
int openUDPSock(char *IP, unsigned short port);
int openTCPSock(char *IP, unsigned short port);
int sendToMsg(int sock, void* buf, int len, int flags, struct sockaddr *dstaddr, int addrlen);
int recvMsgFrom(int sock, void* buf, int len, int flags, struct sockaddr *srcaddr, socklen_t *addrlen);
char* readFile(const char* filename, size_t* len);
