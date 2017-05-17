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

#define BUF_LEN 128
struct sockaddr_in server_addr, client_addr;
char buffer[BUF_LEN], recvBuffer[BUF_LEN];
char temp[20];
int server_fd, client_fd;
int len, msg_size, clntLen, recvLen;


int openTCPSock(char *IP, unsigned short port) {
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {// socket
        printf("Server : Can't open stream socket\n");
        exit(0);
    }
    memset(&server_addr, 0x00, sizeof(server_addr));
    //server_Addr init
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(IP);
    server_addr.sin_port = port;
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0)
    {
        printf("Server : Can't bind local address.\n");
        exit(0);
    }
    
    if (listen(server_fd, 5) < 0)
    {
        printf("Server : Can't listening connect.\n");
        exit(0);
    }
    
    memset(buffer, 0x00, sizeof(buffer));
    printf("Server : wating connection request.\n");
    len = sizeof(client_addr);
    while (1)
    {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
        if (client_fd < 0)
        {
            printf("Server: accept failed.\n");
            exit(0);
        }
        inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
        printf("Server : %s client connected.\n", temp);
        
        msg_size = read(client_fd, buffer, 1024);
        write(client_fd, buffer, msg_size);
        close(client_fd);
        printf("Server : %s client closed.\n", temp);
    }
    close(server_fd);
    return 0;
}


int openUDPSock(char *IP, unsigned short port){
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {// socket
        printf("Server : Can't open stream socket\n");
        exit(0);
    }
    /* servAddr init */
    memset(&server_addr, 0x00, sizeof(server_addr));
    /* servAddr IP and Port */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(IP);
    server_addr.sin_port = port;
    
 
    if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0)
    {
        printf("Server : Can't bind local address.\n");
        exit(0);
    }
    while(1) {
        clntLen = sizeof(client_addr);
   
        if((recvLen=recvfrom(server_fd, recvBuffer, BUF_LEN-1, 0,
                             (struct sockaddr*)&client_addr, &clntLen)) == -1)
        {
            perror("recvfrom failed");
            exit(1);
        }
        recvBuffer[recvLen] = '\0';
        printf("Recevied: %s\n", recvBuffer);
        
        if(sendto(server_fd, recvBuffer, recvLen, 0,
                  (struct sockaddr*)&client_addr, sizeof(client_addr)) != recvLen)
        {
            perror("sendto failed");
            exit(1);
        }
    }
}

void closeSock(int sock)
{
    closesocket(sock);
}



void set_aiocb(struct aiocb *cbp, int fd, void* buffer, size_t size) {
    //fd set
    cbp->aio_fildes     = fd;
    //buffer set
    cbp->aio_buf        = buffer;
    //size set
    cbp->aio_nbytes     = size;
    //fop set
    cbp->aio_offset     = 0;
}


int reg_check(const char* regex, void* buf){

	regex_t state;
	const char *pattern = regex;
	char tmp[100];
	int rc;

	//pattern compile
	rc = regcomp(&state, pattern, REG_EXTENDED);
	if(rc != 0 ){
		regerror(rc, &state, tmp, 100);
		printf("regcomp() failed with '%s'\n", tmp);
		return reg_error_number(rc);
	}	

	//matching regex
	int status = regexec(&state, buf, 0, NULL, 0);
	
	return status;
}


RSA* getPubkey(const char* id){

	FILE *f_key = NULL;
	char* f_name = NULL;
	RSA *pub_rsa = NULL;

	/*RSA Buffer*/
	pub_rsa = RSA_new() ;


	/*id + .pub(4byte)*/
	f_name = (char*)malloc(strlen(id)+ 4);
	sprintf(f_name , "%s.pub", id);


	f_key = fopen(f_name, "r");

	if(f_key < 0){
		perror("file read\n");
		return 0;
	}

	pub_rsa = PEM_read_RSA_PUBKEY(f_key, &pub_rsa,NULL, NULL);

	if(pub_rsa < 0){
		perror("pub read error\n");
		return 0;
	}

	return pub_rsa;
}

int reg_error_number(int error){
	
	switch(error){
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
                        break;
	}
}

ssize_t 
recvMsgUntil(int sock, const char* regex,void* buf, size_t n){

	int ret , len; 
	struct aiocb cb;

	memset(&cb , 0x00, sizeof(struct aiocb));
	set_aiocb(&cb, sock, buf, n);

	ret = aio_read(&cb);
	if (ret < 0) perror("aio_read");
	
	while ( aio_error( &cb ) == EINPROGRESS ){}

	/* got ret bytes on the read */
	if ((len = aio_return(&cb)) > 0) {

	    /*reg check to buf*/
	    ret =reg_check(regex, buf);

	    /*if scucces, retrun value is 0*/
	    if(ret == 0)
		return len;
	    /*if error, return value negative int.*/
	    else 
		return ret;
	
	} else {
	    /* read failed, consult errno */
	    return -1;
	}	
}
