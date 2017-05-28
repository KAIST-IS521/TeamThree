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
#include <regex.h>
#include <gpgme.h>
#include <locale.h>
#include <errno.h>
#include "slalib.h"
#include "gpg.h"

/*
	gpgme error check func
*/
#define fail_if_err(err)                                      \
  do                                                          \
    {                                                         \
      if (err)                                                \
        {                                                     \
          fprintf (stderr, "%s:%d: %s: %s\n",                 \
                   __FILE__, __LINE__, gpgme_strsource (err), \
          gpgme_strerror (err));                              \
          exit (1);                                           \
        }                                                     \
    }                                                         \
  while (0)

/*
	Global var define
*/
int bool_path = 1;
char g_password[100] = {0};

struct Sock* sockList = NULL;
int maxSockfd = -1;

const char* email[] =
{
    "jhong3842@gmail.com",  //jhong3842
    "IS521_TT@kaist.ac.kr", //Team_Three
    "m@frv.ag",             //mfaerevaag
    "jean.cassou-mounat@insa-lyon.fr",//jcassou
    "signal@kait.ac.kr",//KAISTGUN
    "sbahn1992@gmail.com",//sbahn1992
    "alinghi@kaist.ac.kr",//alinghi
    "sangkilc@kaist.ac.kr",//sangkilc
    "cjdhlds08@gmail.com",//asdfljh
    "bjgwak@kaist.ac.kr",//bjgwak
    "yunjong@kaist.ac.kr",//blukat29
    "gksgudtjr456@gmail.com",//DaramG
    "dinggul@kaist.ac.kr",//dinggul
    "prious@kaist.ac.kr",//donghwan17
    "jihyeon.yoon@kaist.ac.kr",//ggoboogy
    "anh1026@kaist.ac.kr",//Hyeongcheol-An
    "ian0371@gmail.com",//ian0371
    "jettijam@gmail.com",//jaemoon-sim
    "jangha@kaist.ac.kr",//james010kim
    "jschoi.2022@gmail.com",//jchoi2022
    "ohkye415@gmail.com",//JeongOhKye
    "jmpark81@kaist.ac.kr",//jmpark81
    "juanaevv@nate.com",//juanaevv
    "lbh0307@gmail.com",//lbh0307
    "jsoh921@kaist.ac.kr",//mickan921
    "kmb1109@kaist.ac.kr",//mikkang
    "nhkwak@kaist.ac.kr",//nohkwak
    "pr0v3rbs@kaist.ac.kr",//pr0v3rbs
    "su3604@kaist.ac.kr",//seongil-wi
    "seungwonwoo@kaist.ac.kr",//seungwonwoo
    "soomink@kaist.ac.kr"//soomin-kim
};

const char* github_id[] =
{
    "jhong3842",
    "Team_Three",   //server
    "mfaerevaag",
    "jcassou",
    "KAISTGUN",
    "sbahn1992",
    "alinghi",
    "sangkilc",
    "asdfljh",
    "bjgwak",
    "blukat29",
    "DaramG",
    "dinggul",
    "donghwan17",
    "ggoboogy",
    "Hyeongcheol-An",
    "ian0371",
    "jaemoon-sim",
    "james010kim",
    "jchoi2022",
    "JeongOhKye",
    "jmpark81",
    "juanaevv",
    "lbh0307",
    "mickan921",
    "mikkang",
    "nohkwak",
    "pr0v3rbs",
    "seongil-wi",
    "seungwonwoo",
    "soomin-kim"
};

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

int handshake(int sock, const char* ID, const char* serverFprt, const char* passphrase, const char* successMsg, int debug)
{
    int result = 0;
    char challenge[4096];
    char dec[4096];
    char enc[1024];
    char signerFprt[100];
    char* tmp;
    char random_number[100];
    int length = 0;
    ssize_t ret_size;

    result = sendMsg(sock, ID, strlen(ID));
    if (result != -1)
    {
        ret_size = recv(sock, challenge, 4096, 0);
        if (ret_size != -1)
        {
            if (debug) printf("challenge!!!\n%s\n", challenge);

            decrypt(challenge, dec, passphrase);
            if (debug) printf("decrypt!!!\n%s\n", dec);

            verify(dec, signerFprt);
            if (debug) printf("fingerprint!!!\n%s\n", signerFprt);

            if (strcmp(signerFprt, serverFprt) == 0)
            {
                if (debug) printf("sign verified!!!\n");
                tmp = strstr(dec, "\n\n");
                length = strstr(tmp, "-----BEGIN PGP SIGNATURE-----") - tmp;
                strncpy(random_number, tmp + 2, length - 3);
                if (debug) printf("random number!!!\n%s\n", random_number);

                encrypt(random_number, serverFprt, enc);
                if (debug) printf("encrypt!!!\n%s\n", enc);

                result = sendMsg(sock, enc, strlen(enc));
            }
            else if (debug) printf("sign unverified!!!\n");
        }
        else if (debug) printf("recvMsgUntil fail!\n");
    }
    else if (debug)
        printf("sendMsg fail!\n");

    result = (int)recv(sock, successMsg, 1024, 0);
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
        struct sockaddr_in* addr = &sockList[sock].addr;
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
        struct sockaddr_in* addr = &sockList[sock].addr;
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

void read_file(const char* filename)
{
    FILE *fd = 0 ;
    int size = 0 ;
    fd = fopen(filename, "r");

    if(fd == 0){
        perror("read error");
        return;
    }
    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    if(size > 100){
        perror("read size big\n");
        return -1;
    }
    fread(g_password, 1 , size, fd);

    fclose(fd);
}
