#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "slalib.h"
//소켓 프로그래밍에 사용될 헤더파일 선언

#define BUF_LEN 128
//메시지 송수신에 사용될 버퍼 크기를 선언

int main(int argc, char *argv[])
{
        struct sockaddr_in server_addr, client_addr;
        char temp[20];
        int server_fd, client_fd;
        //server_fd, client_fd : 각 소켓 번호
        int len, msg_size;


	/*gpgme*/
        gpgme_ctx_t ctx;  // the context
        gpgme_error_t err; // errors
        gpgme_key_t key[2] = {NULL, NULL}; // the key
        gpgme_data_t clear_buf, encrypted_buf, import_key_buf, decrypted_buf, send_buf,recv_buf; // plain buf, encryped buf
        gpgme_user_id_t user; //the users
        unsigned char* rand_number =NULL;
        unsigned char* buffer = NULL;
        gpgme_encrypt_result_t  result;
        ssize_t nbytes;

        int index = 0;

        //allocation dec/enc data
        buffer = (unsigned char*)malloc(4096);


	rand_number = gen_rand_num();
	/*Init gpgme*/
        init_gpgme(&ctx);



	//TODO : setting password
        //setting password of the private key
        passphrase_gpgme(ctx, "passowrd");

        //get the key encryption
        get_gpgme_key(ctx, &key, 0, "Team_Three");

        //prepare of the buffer to using
        set_gpgme_buffer(&clear_buf, &encrypted_buf, rand_number, &decrypted_buf);


        if(argc != 2)
       {
            printf("usage : %s [port]\n", argv[0]);
            exit(0);
        }

        if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {// 소켓 생성
            printf("Server : Can't open stream socket\n");
            exit(0);
        }
        memset(&server_addr, 0x00, sizeof(server_addr));
        //server_Addr 을 NULL로 초기화

        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons(atoi(argv[1]));
        //server_addr 셋팅

        if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0)
        {//bind() 호출
            printf("Server : Can't bind local address.\n");
            exit(0);
        }

        if(listen(server_fd, 5) < 0)
        {//소켓을 수동 대기모드로 설정
            printf("Server : Can't listening connect.\n");
            exit(0);
        }

        memset(buffer, 0x00, sizeof(buffer));
        printf("Server : wating connection request.\n");
        len = sizeof(client_addr);
        while(1)
        {
            client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
            if(client_fd < 0)
            {
                printf("Server: accept failed.\n");
                exit(0);
            }
            inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
            printf("Server : %s client connected.\n", temp);

	    gpgme_data_new(&send_buf);
	    gpgme_data_new(&recv_buf);
            /*
		Decrypt and Encrypt rountine
	    */

	    //recv data is encrypted random number by github public key
            msg_size = read(client_fd, buffer, 4096);


           printf("recv data : %s\n",buffer);
           //encrypted data copy from memory
           err=gpgme_data_new_from_mem(&recv_buf,buffer,strlen(buffer),1);

	   //decrypt encrypted data
           err = gpgme_op_decrypt(ctx, recv_buf, decrypted_buf);

           //memory init
           memset(buffer, 0x00, 4096);

           //read data
           read_data_gpgme(buffer, decrypted_buf);


	    printf("############################Decrypthon Random Number#############################\n");
	    for(index = 0 ; index < 128 ; index++){
                if(index % 16 == 0&& index !=0) printf("\n");
                printf("%02x ", buffer[index]);
	    }
	    printf("\n################################################################################\n");

	   err=gpgme_data_new_from_mem(&encrypted_buf,buffer,128 ,1);

	   /*
		encrypt random number with publickey other
	   */
	   encrypt_gpgme(ctx, key, encrypted_buf, send_buf);

    	   //memory init
           memset(buffer, 0x00, 4096);

	   //read data
	   read_data_gpgme(buffer, send_buf);

	   printf("to send data : %s\n",buffer);


           write(client_fd, buffer, strlen(buffer));
	   gpgme_data_release(send_buf);


	   write(client_fd, "Connected",strlen("Connected"));

           close(client_fd);
           printf("Server : %s client closed.\n", temp);
        }
        close(server_fd);
        return 0;
}

