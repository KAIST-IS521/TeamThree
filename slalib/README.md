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
    * This function reads in maximum n bytes fro the given socket.
    * `return -1`: Failed to read.
    * `reg_error_number`
```
 		case REG_NOMATCH:
			return -11;
			break;
                case REG_BADPAT:
                        return -12;
                        break;
                case REG_ECOLLATE:
                        return -13;
                        break;
                case REG_ECTYPE:
                        return -14;
                        break;
                case REG_EESCAPE:
                        return -15;
                        break;
                case REG_ESUBREG:
                        return -16;
                        break;
                case REG_EBRACK:
                        return -17;
                        break;
                case REG_EPAREN:
                        return -18;
                        break;
                case REG_EBRACE:
                        return -19;
                        break;
                case REG_BADBR:
                        return -20;
                        break;
                case REG_ERANGE:
                        return -21;
                        break;
                case REG_ESPACE:
                        return -22;
                        break;
                case REG_BADRPT:
                        return -23;
```

* **`int sendMsg(int sock, const char* buf, size_t n)`**
    * This function sends a string to the connected socket.
    * `return -1`: Failed to read.

* **`int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg)`**
    * This function performs PGP-based authentication.
    * `return -1`: Not maching succuss Message.
    * `return -2`: Not correct decryption number.

