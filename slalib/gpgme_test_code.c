#include "stdio.h"
#include "slalib.h"


#define fail_if_err(err)                                        \
  do                                                            \
    {                                                           \
      if (err)                                                  \
        {                                                       \
          fprintf (stderr, "%s:%d: %s: %s\n",                   \
                   __FILE__, __LINE__, gpgme_strsource (err),   \
                   gpgme_strerror (err));                       \
          exit (1);                                             \
        }                                                       \
    }                                                           \
  while (0)

int main()
{
	gpgme_ctx_t ctx;  // the context
        gpgme_error_t err; // errors
        gpgme_key_t key[2] = {NULL, NULL}; // the key	
        gpgme_data_t clear_buf, encrypted_buf, import_key_buf, decrypted_buf; // plain buf, encryped buf
	gpgme_user_id_t user; //the users
	unsigned char* rand_number =NULL;
	unsigned char* buffer = NULL;
	gpgme_encrypt_result_t  result;
	ssize_t nbytes;

	int index = 0;

	//create random number
	rand_number = gen_rand_num();	
	//allocation dec/enc data
	buffer = (unsigned char*)malloc(4096);

	printf("#####################Gen Random Number###########################\n");
	//debug
	for(index = 0 ; index < 128 ; index++){
		
		if(index % 16 == 0&& index !=0) printf("\n");
		printf("%02x ", rand_number[index]);

	}
	printf("\n###############################################################\n");

	//init to gpgme
	init_gpgme(&ctx);

	//setting password of the private key
	gpgme_set_passphrase_cb(ctx, passphrase_cb, NULL);


	//get the key encryption
	get_gpgme_key(ctx, &key, 1);

	//prepare of the buffer to using
	set_gpgme_buffer(&clear_buf, &encrypted_buf, rand_number, &decrypted_buf);

	//debug
	user = key[0] -> uids;	
	printf("\nEncrypting for %s <%s>\n\n", user->name, user->email);


	//import key 
	import_key_gpgme(ctx, "/home/richong/TeamThree/slalib/TTprivate.key",&import_key_buf);


	//encrypt random data
	encrypt_gpgme(ctx, key,clear_buf, encrypted_buf);


	//read data
	read_data_gpgme(buffer, encrypted_buf);
	
	//debug
	printf("\n#########################-Encrytption Data###########################\n\n%s\n\
#######################################################################\n\n",buffer);

	//encrypted data copy from memory
	err=gpgme_data_new_from_mem(&encrypted_buf,buffer,strlen(buffer),1);

	//decrypt encrypted data
        err = gpgme_op_decrypt(ctx, encrypted_buf, decrypted_buf);	

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

}
