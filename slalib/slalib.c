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
#include <gpgme.h>
#include <locale.h>
#include <errno.h>

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

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
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

void closeSock(int sock)
{
    close(sock);
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

/*
	reg check
*/
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


/*
	Generate 128 random numbers
*/

unsigned char* gen_rand_num(){

        unsigned char *buf = NULL;
        int index = 0;
        int fd = 0;
        unsigned int seed = 0;

        fd = fopen("/dev/urandom","rb");
        fread(&seed, 4, 1, fd);
        fclose(fd);
        srand((unsigned int)seed);
	
	buf = (unsigned char*)malloc(128);

	while(index < 128){
		buf[index]= rand() % (0xff + 1);
		index ++;
	}

	return buf;
	

}


 
/*
	gpg_init setting.
	Version check and key ring dir setting
	neseccery import pub/pri key
*/
void init_gpgme(gpgme_ctx_t *ctx){

	gpgme_error_t err;
	gpgme_engine_info_t info;
	setlocale (LC_ALL, ""); // set the locale
	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL)); // set gpgme locale
	gpgme_check_version(NULL); // initialize gpgme
	err = gpgme_new (ctx); // initialize the context
	gpgme_set_armor(*(gpgme_ctx_t *)ctx, 1);

	err = gpgme_ctx_set_engine_info (*(gpgme_ctx_t *)ctx, GPGME_PROTOCOL_OpenPGP, "/usr/bin/gpg", "~/.gnupg/");
 	fail_if_err(err);

}


/*
	setting buffer to gpgme_data format
*/
void set_gpgme_buffer(gpgme_data_t *plain_buf, gpgme_data_t *encrypted_buf,
		      unsigned char* plain, gpgme_data_t *decrypted_buf){
	gpgme_error_t err;

	/* Prepare the data buffers */
	err = gpgme_data_new_from_mem(plain_buf, plain, 128, 1);
 	fail_if_err(err);
        err = gpgme_data_new(encrypted_buf);
        fail_if_err(err);
	err = gpgme_data_new(decrypted_buf);
	fail_if_err(err);

	
}



/*
	Getting the pri or pub key in the key ring
*/
void get_gpgme_key(gpgme_ctx_t ctx, gpgme_key_t **key, int public, const char* id){

	gpgme_error_t err;
	char name[100] = {0};
	int index = 0;

	for(index = 0 ; index < 32; index ++){
		if(!strcmp(github_id[index], id)) break;
	}


	/*For test name*/
	strcpy(name, email[index]);

	/*start the keylist*/
	err = gpgme_op_keylist_start (ctx ,name, public);
	fail_if_err(err);

	/*keylist searching*/
	err =  gpgme_op_keylist_next(ctx, (gpgme_key_t*)&key[0]);
	fail_if_err(err);

	/*keylist end*/	
	err = gpgme_op_keylist_end(ctx);
	fail_if_err(err);

}


/*
	Encrypt plaintext with key
*/
void encrypt_gpgme(gpgme_ctx_t ctx, gpgme_key_t *key, 
			gpgme_data_t clear_buf, gpgme_data_t encrypted_buf){

        gpgme_error_t err;
        gpgme_encrypt_result_t  result;

        err = gpgme_op_encrypt(ctx, key,
                          GPGME_ENCRYPT_ALWAYS_TRUST, clear_buf, encrypted_buf);

        fail_if_err(err);
        result = gpgme_op_encrypt_result(ctx);

        if (result->invalid_recipients){
                fprintf (stderr, "Invalid recipient found: %s\n",
                result->invalid_recipients->fpr);
                exit (1);
        }

}


/*
	Read data gpgme_data_t 
*/
void read_data_gpgme(unsigned char* buffer, gpgme_data_t encrypted_buf){

	ssize_t nbytes;

        nbytes = gpgme_data_seek (encrypted_buf, 0, SEEK_SET);
        if (nbytes == -1) {
	        fprintf (stderr, "%s:%d: Error in data seek: ",
        	         __FILE__, __LINE__);
	        perror("");
	        exit (1);
        }


        //buffer = (unsigned char*)malloc(4096);
        nbytes = gpgme_data_read(encrypted_buf, buffer, 4096);
	buffer[nbytes] = '\x00';

}
/*
	Import private key
*/

void import_key_gpgme(gpgme_ctx_t ctx ,const char* key_path, gpgme_data_t *key_data){

	gpgme_error_t err;
	int key_fd;

	key_fd = open(key_path, O_RDONLY);
	if(key_fd == -1){
                fprintf (stderr, "%s:%d: Error in data seek: ",
                __FILE__, __LINE__);
                perror("");
                exit (1);

	}

	err = gpgme_data_new_from_fd(key_data, key_fd);
        fail_if_err(err);

	err = gpgme_op_import(ctx, *(gpgme_data_t*)key_data);
	fail_if_err(err);
}

/*
	callback function passphrase_cb
*/

gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint,
                             const char *passphrase_info,
                             int prev_was_bad, int fd){
   char phrase[103];

   if (bool_path) {
      strncpy(phrase, hook, strlen(hook));
      strcat(phrase, "\n");
      write (fd, phrase, strlen(phrase));
   }
 
  return 0;
}


/*
	Register password 
	passphrase_cb setting
*/
void passphrase_gpgme(gpgme_ctx_t ctx,char* password){

	gpgme_set_passphrase_cb(ctx, passphrase_cb, password);
}


int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg){



	/*gpgme var*/
        gpgme_ctx_t ctx;  // the context
        gpgme_error_t err; // errors
        gpgme_key_t key[2] = {NULL, NULL}; // the key
	gpgme_key_t pri_key[2]  = {NULL, NULL};
	/*
		clear_buf is random number
		enctypted_buf is encrypted random number
		import_key_buf is to import private key of priKeyPath
		decrypted_buf is to decrypt enctypted data
		recv_buf is to data encrypted by public key 
	*/
        gpgme_data_t clear_buf, encrypted_buf, import_key_buf, decrypted_buf, recv_buf; // plain buf, encryped buf
	gpgme_user_id_t user; //the users
        gpgme_encrypt_result_t  result; // result

	/*other var*/
        unsigned char* rand_number =NULL;
        unsigned char* buffer = NULL;
        ssize_t nbytes;
        int index = 0;


        /*if private key dont using  a password*/
        if( passPath == NULL){
                bool_path = 0;
        }

#if 0
        //create random number to auth
        rand_number = gen_rand_num();
#endif // FIXME - SLA checker does not generate random number
	/*
		read password
	*/
	read_file(passPath);

#if 0
        //allocation dec/enc data
        buffer = (unsigned char*)malloc(4096);

        printf("#####################Gen Random Number###########################\n");
        for(index = 0 ; index < 128 ; index++){

                if(index % 16 == 0&& index !=0) printf("\n");
                printf("%02x ", rand_number[index]);

        }
        printf("\n###############################################################\n");
#endif // FIXME - SLA checker does not generate random number
        /*
		init to gpgme
	*/
        init_gpgme(&ctx);
	gpgme_data_new(&recv_buf);

	
	
        /*
		setting password of the private key
	*/
        gpgme_set_passphrase_cb(ctx, passphrase_cb, g_password);

        /*
		prepare of the buffer to using
	*/
        set_gpgme_buffer(&clear_buf, &encrypted_buf, rand_number, &decrypted_buf);

	/*
		 import private key
		 priKeyPath is import file name
		 ex)
			/tmp/user.pri --> file
			
			/tmp/user.pri [O]
			/tmp/	      [x]
	*/
        import_key_gpgme(ctx, privKeyPath ,&import_key_buf);

        /*
		get the key encryption
		key is the pub 
	*/
        get_gpgme_key(ctx, &key, 0, ID);


        /*
		encrypt random data
	*/
        encrypt_gpgme(ctx, key ,clear_buf, encrypted_buf);

        /* 	
		read data
		buffer has a ascii encrypted data
		to send
	*/
        read_data_gpgme(buffer, encrypted_buf);

        /*
		Print buffer data
	*/
        printf("\n#########################-Encrytption Data to send###########################\n\n%s\n\
#######################################################################\n\n",buffer);


	/*
		Send Data is encrypted by github id public key
	*/
	aio_send(sock, buffer, 4096);


        /*
                Recv Data is data encrypted by server public key
        */
        memset(buffer, 0x00, 4096);
	nbytes = aio_recv(sock,buffer, 4096);

	buffer[nbytes] = '\x00';
        //encrypted data copy from memory
        err=gpgme_data_new_from_mem(&recv_buf,buffer,strlen(buffer),1);

        printf("\n\n#########################-Encrytption Data by server public###########################\n%s\n\
#######################################################################\n\n",buffer);


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



	/*
		cmp origin rand number and recv data
	*/

	if(confirm_randnum(rand_number, buffer)){
		memset(buffer, 0x00, 4096);
        	nbytes = aio_recv(sock,buffer, 4096);
			
		/*recv success Msg return 1*/
		if(!strcmp(buffer,successMsg))
			return 1;

		/*not matching success Msg*/
		else
			return -1;
		
		
	}
	else {
		/*not correct decrytion number*/
		return -2;
	}	
		
}


ssize_t 
aio_send(int sock, void* buf, size_t n){

        int ret , len; 
        struct aiocb cb;

        memset(&cb , 0x00, sizeof(struct aiocb));
        set_aiocb(&cb, sock, buf, n);

        ret = aio_write(&cb);
        if (ret < 0) perror("aio_read");
        
        while ( aio_error( &cb ) == EINPROGRESS ){}

        /* got ret bytes on the read */
	if ((len = aio_return(&cb)) > 0) {
              return len;
	} else {
          /* read failed, consult errno */
          return -1;
      }       
}

ssize_t
aio_recv(int sock, void* buf, size_t n){

        int ret , len;
        struct aiocb cb;

        memset(&cb , 0x00, sizeof(struct aiocb));
        set_aiocb(&cb, sock, buf, n);

        ret = aio_read(&cb);
        if (ret < 0) perror("aio_read");

        while ( aio_error( &cb ) == EINPROGRESS ){}

        /* got ret bytes on the read */
        if ((len = aio_return(&cb)) > 0) {
              return len;
        } else {
          /* read failed, consult errno */
          return -1;
      }
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

int confirm_randnum(unsigned char *org, unsigned char *cmp){
	
	int index = 0;
	int count = 0;

	for(index < 0 ; index < 128; index++){
		if(org[index] == cmp[index])
			count++;
	}

	if(count == 128)
		return 1;
	else
		return 0;
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

