#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <aio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <regex.h>
#include "slalib.h"






int main(int argc, char *argv[]) {

	int cli_fd, len;
	struct sockaddr_in client_addr;
	char* buf = NULL;

	/*for develop, test code*/
	cli_fd = socket(PF_INET, SOCK_STREAM, 0);

	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	client_addr.sin_port = htons(9999);

	if(connect(cli_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1) perror("connect error\n");

	buf =(void*) malloc(4096);


    if(
	handshake(cli_fd,"jhong3842",
	"/home/richong/tmp/TeamThree/slalib/TTprivate.key",
	"/home/richong/tmp/TeamThree/slalib/pass",
	"Connected")){
		printf("\n--------------------------handshake success------\n");
	}

	//recvMsgUntil(cli_fd, buf, 4096);

	close(cli_fd);
	return 0;
}

/*
ssize_t
recvMsgUntil(int sock, void* buf, size_t n){

	int ret , len;
	struct aiocb cb;

	memset(&cb , 0x00, sizeof(struct aiocb));
	set_aiocb(&cb, sock, buf, n);

	ret = aio_read(&cb);
	if (ret < 0) perror("aio_read");

	while ( aio_error( &cb ) == EINPROGRESS ){}

	/* got ret bytes on the read */
//	if ((len = aio_return(&cb)) > 0) {
//
//		return len;
//
//	} else {
//	    /* read failed, consult errno */
//	    return -1;
//	}
//}*/
