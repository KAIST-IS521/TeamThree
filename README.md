# SLA Library

## Install


## Library function

* `int openTCPSock(char *IP, unsigned short port)`
 ** 

* `int openUDPSock(char *IP, unsigned short port)`
 ** 

* `void closeSock(int sock)`
 ** 

* `ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n)`
 ** 

* `sendMsg(int sock, const char* buf, size_t n)`
 ** 

* `int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg)`
 ** 
