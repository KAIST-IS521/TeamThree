#include <arpa/inet.h>
#include <aio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <regex.h>
#include <gpgme.h>
#include <locale.h>
#include <errno.h>
#include "slalib.h"
#include "gpg.h"

/*
	Global var define
*/
struct Sock* sockList = NULL;
int maxSockfd = -1;

void initSockList()
{
    if (sockList == NULL)
    {
        sockList = malloc(sizeof(struct Sock));
        if (sockList == NULL)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        maxSockfd = 0;
    }
}

void resizeSockList(int sockfd)
{
    if (maxSockfd < sockfd)
    {
        sockList = realloc(sockList, sizeof(struct Sock) * (sockfd + 1));
        if (sockList == NULL)
        {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        maxSockfd = sockfd;
    }
}

int openTCPSock(char *IP, unsigned short port)
{
    int sock_fd;
    struct sockaddr_in addr;

    initSockList();

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {// socket
        printf("%s : Failed to open socket\n", __FUNCTION__);
        return -1;
    }

    // set up addr
    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, IP, &addr.sin_addr) != 1)
    {
        printf("%s: Failed in inet_pton()\n", __FUNCTION__);
        close(sock_fd);
        return -1;
    }

    // connect
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock_fd);
        return -1;
    }

    resizeSockList(sock_fd);
    sockList[sock_fd].type = TCP;

    // return the socket handle
    return sock_fd;
}

int openUDPSock(char *IP, unsigned short port)
{
    int sock_fd;
    struct sockaddr_in *addr;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {// socket
        printf("%s : Failed to open socket\n", __FUNCTION__);
        return -1;
    }

    resizeSockList(sock_fd);
    sockList[sock_fd].type = UDP;
    addr = &sockList[sock_fd].addr;

    // set up addr
    memset(addr, 0x00, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if (inet_pton(AF_INET, IP, &addr->sin_addr) != 1)
    {
        printf("%s: Failed in inet_pton()\n", __FUNCTION__);
        close(sock_fd);
        return -1;
    }

    // return the socket handle
    return sock_fd;
}

void closeSock(int sock)
{
    close(sock);
}

int handshake(int sock, const char* ID,
              const char* privKeyPath,
              const char* passPath,
              const char* successMsg)
{
    int result = 0;

    // Server cipher
    ssize_t cipherLen;
    char cipherStr[4096];
    char *signerFpr;

    // Decrypted message
    ssize_t plainLen;
    char *plainStr;

    // reEncrypted message
    ssize_t authLen;
    char *authStr;

    // Private PGP key
    size_t privKeyLen;
    char *passphrase, *privKey;

    // Final message
    size_t resMsgLen = strlen(successMsg);
    char *resMsg;

    passphrase = readFile(passPath, NULL);
    if (passphrase == NULL)
    {
        return -1;
    }

    privKey = readFile(privKeyPath, &privKeyLen);
    if (privKey == NULL)
    {
        free(passphrase);
        return -1;
    }

    result = sendMsg(sock, ID, strlen(ID));
    if (result == -1) // sendMsg failed
    {
        free(passphrase);
        free(privKey);
        return -1;
    }

    cipherLen = recvMsgUntil(sock, ".*" "-----END PGP MESSAGE-----\n",
                             cipherStr, sizeof(cipherStr) - 1);
    if (cipherLen == -1)
    {
        free(passphrase);
        free(privKey);
        return -1;
    }

    plainLen = decrypt_verify(cipherStr, cipherLen,
                              privKey, privKeyLen, passphrase,
                              &plainStr, &signerFpr);
    free(passphrase);
    free(privKey);
    if (plainLen == -1)
        return -1;

    authLen = encrypt(plainStr, plainLen, signerFpr, &authStr);
    free(plainStr);
    if (authLen == -1)
        return -1;

    result = sendMsg(sock, authStr, authLen);
    free(authStr);
    if (result == -1)
        return -1;

    resMsg = malloc(resMsgLen + 1);
    resMsg[resMsgLen] = '0';

    result = recvMsgUntil(sock, successMsg, resMsg, resMsgLen);
    if (result == -1)
    {
        free(resMsg);
        return -1;
    }

    result = !strncmp(resMsg, successMsg, resMsgLen) ? 0 : -1;
    free(resMsg);
    return result;
}

int sendMsg(int sock, const char* buf, size_t n)
{
    const char* ptr = buf;
    int ns;

    if (sockList[sock].type == TCP)
    {
        while (n > 0)
        {
            ns = send(sock, ptr, n, 0);
            if (ns < 1)
                return -1;

            ptr += ns;
            n -= ns;
        }
    }
    else // UDP socket
    {
        struct sockaddr* addr = (struct sockaddr*)&sockList[sock].addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        while (n > 0)
        {
            ns = sendto(sock, ptr, n, 0, addr, addrlen);
            if (ns < 1)
                return -1;

            ptr += ns;
            n -= ns;
        }
    }
    return 0;
}

ssize_t recvMsgUntil(int sock, const char* regex, void* buf, size_t n)
{
    char* sbuf = buf;
    regex_t state;
    size_t cnt = 0;
    int nr;

    if (regcomp(&state, regex, REG_EXTENDED) != 0)
    {
        perror("regcomp");
        return -1;
    }

    bzero(buf, n);

    if (sockList[sock].type == TCP)
    {
        while (cnt < n)
        {
            nr = recv(sock, &sbuf[cnt++], 1, 0);
            if (nr == -1)
            {
                regfree(&state);
                return -1;
            }
            else if (nr == 0) // EOF
            {
                cnt--;
                break;
            }

            // NOTE: Buggy if buf has size exact n
            if (regexec(&state, buf, 0, NULL, 0) == 0)
                break;
        }
    }
    else // UDP socket
    {
        struct sockaddr* addr = (struct sockaddr*)&sockList[sock].addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        while (cnt < n)
        {
            if ((nr = recvfrom(sock, &sbuf[cnt++], 1, 0, addr, &addrlen)) == -1)
            {
                regfree(&state);
                return -1;
            }
            else if (nr == 0) // 0 length datagram does not mean EOF
            {
                cnt--;
                continue;
            }

            // NOTE: Buggy if buf has size exact n
            if (regexec(&state, buf, 0, NULL, 0) == 0)
                break;
        }
    }

    regfree(&state);
    return cnt;
}

char* readFile(const char* filename, size_t* len)
{
    struct stat st;
    char *buf;
    FILE *fp;
    ssize_t nr;

    bzero(&st, sizeof(st));
    if (stat(filename, &st) != 0)
    {
        perror("stat");
        return NULL;
    }
    buf = malloc(st.st_size);
    if (buf == NULL)
    {
        perror("malloc");
        return NULL;
    }

    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        perror("fopen");
        free(buf);
        return NULL;
    }
    nr = fread(buf, st.st_size, 1, fp);
    if (nr == -1 || nr != (ssize_t)st.st_size)
    {
        perror("fread");
        free(buf);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    if (len != NULL)
        *len = st.st_size;
    return buf;
}
