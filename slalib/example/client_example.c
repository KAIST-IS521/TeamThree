#include <stdio.h>
#include <stdlib.h>
#include "slalib.h"

#define GITHUB_ID "IS521_TT"
#define KEYPATH "/home/lbh/TTprivate.key"
#define PASSPATH "/home/lbh/TTprivate.pass"

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s [PORT]\n", argv[0]);
        return 0;
    }

    int sock = openTCPSock("127.0.0.1", atoi(argv[1]));
    int ret = handshake(sock, GITHUB_ID, KEYPATH, PASSPATH, "success");
    printf("handshake: %d", ret);
    return 0;
}
