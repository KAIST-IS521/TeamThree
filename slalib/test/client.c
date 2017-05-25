#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include "../slalib.h"

#define GITHUB_ID ""
#define SERVER_FINGERPRINT ""
#define CLIENT_PASSPHRASE ""
#define DEBUG 1

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: client [PORT]\n");
        return 0;
    }

    char ret[1024];
    int sock = openTCPSock("127.0.0.1", atoi(argv[1]));
    handshake(sock, GITHUB_ID, SERVER_FINGERPRINT, CLIENT_PASSPHRASE, ret, DEBUG);
    printf("result - %s\n", ret);

    return 0;
}
