# SLA Library

## Library function

* **`int openTCPSock(char *IP, unsigned short port)`**
    * This function open TCP socket with provided IP and Port.
	* Return Value : sockfd
    * `return -1`: Failed to open socket.

* **`int openUDPSock(char *IP, unsigned short port)`**
    * This function open UCP socket with provided IP and Port.
	* Note that UDP is connectionless so it saves sock info for later use.
	* Return Value : sockfd
    * `return -1`: Failed to open socket.

* **`void closeSock(int sock)`**
    * This function closes the socket.

* **`ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n)`**
    * This function stands for TCP protocol.
    * This function reads in maximum n bytes from the given socket.
	* Return Value : length of recieved data
    * `return -1`: Failed to read.
	* Even though regex never matched, it can return positive value.

* **`int sendMsg(int sock, const char* buf, size_t n)`**
    * This function stands for TCP protocol.
    * This function sends a string to the connected socket.
	* `return 0`: Succeeded to send all data.
    * `return -1`: Failed to send.

* **`int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg)`**
    * This function performs PGP-based authentication.
	* `return 0`: handshake succeeded.
    * `return -1`: handshake failed.
