#pragma once

//SLA Functions
ssize_t recvMsgUntil(int sock, const char* regex,void* buf, size_t n);
int sendMsg(int sock, const char* buf, size_t n);
int handshake(int sock, const char* ID, const char* serverFprt, const char* passphrase, const char* successMsg, int debug);
void closeSock(int sock);
int openUDPSock(char *IP, unsigned short port);
int openTCPSock(char *IP, unsigned short port);
void read_file(const char* filename);
