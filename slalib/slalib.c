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
	srand((unsigned int)time(NULL));
	
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

	err = gpgme_ctx_set_engine_info (*(gpgme_ctx_t *)ctx, GPGME_PROTOCOL_OpenPGP, NULL, "~/.gnupg/");
 	fail_if_err(err);

}


/*
setting buffer to gpgme_data format
*/
void set_gpgme_buffer(gpgme_data_t *buf, unsigned char* plain){
	gpgme_error_t err;
	/* Prepare the data buffers */
	err = gpgme_data_new_from_mem(buf, plain, 128, 1);
 	fail_if_err(err);
}



/*
Getting the pri or pub key in the key ring
*/
void get_gpgme_key(gpgme_ctx_t ctx, gpgme_key_t *key, int public){

	gpgme_error_t err;

	/*For test name*/
	const char *name = "Jaehong kim";

	/*start the keylist*/
	err = gpgme_op_keylist_start (ctx ,name, public);
	fail_if_err(err);

	/*keylist searching*/
	err =  gpgme_op_keylist_next(ctx, key);
	fail_if_err(err);

	/*keylist end*/	
	err = gpgme_op_keylist_end(ctx);
	fail_if_err(err);

}


int handshake(int sock, const char* ID, const char* privKeyPath, const char* passPath, const char* successMsg){
	gpgme_ctx_t ctx;  // the context
	gpgme_error_t err; // errors
	gpgme_key_t key; // the key
	gpgme_data_t clear_buf, encrypted_buf; // plain buf, encryped buf
	unsigned char* rand_number = NULL; //rand number pointer

	/*create random number*/
	rand_number = gen_rand_num();
		
	/*To gpgme, init setting*/
	init_gpgme(&ctx);
	
	/*Setting gpgme buffer*/
	set_gpgme_buffer(&clear_buf, rand_number);	

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
