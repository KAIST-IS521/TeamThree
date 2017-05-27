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
#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s\n",			\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err));			\
          exit (1);						\
        }							\
    }								\
  while (0)

/*
	Global var define
*/
int bool_path = 1;
char g_password[100] = {0};

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

#define BUF_LEN 128
struct sockaddr_in server_addr, client_addr;
char buffer[BUF_LEN], recvBuffer[BUF_LEN];
char temp[20];
int server_fd, client_fd;
int len, msg_size, clntLen, recvLen;

int openTCPSock(char *IP, unsigned short port) {
    int sock_fd;
    struct sockaddr_in addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {// socket
        printf("%s : Failed to open socket\n", __FUNCTION__);
        return -1; // FIXME - Add meaningful return value
    }

    // set up addr
    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if(inet_pton(AF_INET, IP, &addr.sin_addr) < 0){
        printf("%s: Failed in inet_pton()\n", __FUNCTION__);
        return -2; // FIXME - Add meaningful return value
    }

    // connect
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) <0)
    {
        printf("%s : Failed in connect()\n", __FUNCTION__);
        return -3; // FIXME - Add meaningful return value
    }

    // return the socket handle
    return sock_fd;
}

int openUDPSock(char *IP, unsigned short port){
    int sock_fd;
    struct sockaddr_in addr;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {// socket
        printf("%s : Failed to open socket\n", __FUNCTION__);
        return -1; // FIXME - Add meaningful return value
    }

    // set up addr
    memset(&addr, 0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if(inet_pton(AF_INET, IP, &addr.sin_addr) < 0){
        printf("%s: Failed in inet_pton()\n", __FUNCTION__);
        return -2; // FIXME - Add meaningful return value
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
    return (int)send(sock, buf, n, 0);
}

ssize_t recvMsgUntil(int sock, const char* regex, char* buf, size_t n)
{
    regex_t state;
    int ret;
    char* cur = buf;

    ret = regcomp(&state, regex, REG_EXTENDED);
    if (ret != 0)
    {
        return -1;
    }

    while (n > 0)
    {
        recv(sock, cur, 1, 0);
        cur++;
        n--;
        ret = regexec(&state, buf, 0, NULL, 0);
        if (!ret)
            break;
    }

    return cur - buf;
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
