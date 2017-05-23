# SLA Library

## Library function

* **`int openTCPSock(char *IP, unsigned short port)`**
 * This function open TCP socket which provided IP and Port.
 * `return -1`: Failed to open socket.
 * `return -2`: Failed in inet_pton().
 * `return -3`: Failed in connect().

* **`int openUDPSock(char *IP, unsigned short port)`**
 * This function open UCP socket which provided IP and Port.
 * `return -1`: Failed to open socket.
 * `return -2`: Failed in inet_pton().

* **`void closeSock(int sock)`**
 * This function closes the socket.

* **`ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n)`**
 * 

* **`int sendMsg(int sock, const char* buf, size_t n)`**
 * This function sends a string to the connected socket.
 * `return -1`: Failed to read.

* **`int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg)`**
 * 
