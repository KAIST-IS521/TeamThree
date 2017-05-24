#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <gpgme.h>
#include <locale.h>


void init_gpgme2(gpgme_ctx_t *ctx)
{
    gpgme_error_t err;
    setlocale(LC_ALL, ""); // set the locale
    gpgme_check_version(GPGME_PROTOCOL_OpenPGP); // initialize gpgme
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL)); // set gpgme locale
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP); // initialize gpgme

    err = gpgme_new(ctx); // initialize the context
    gpgme_set_armor(*ctx, 1);

    err = gpgme_ctx_set_engine_info(*(gpgme_ctx_t *)ctx, GPGME_PROTOCOL_OpenPGP, "/usr/bin/gpg", "~/.gnupg/");
}

gpgme_error_t passphrase_cb2(void *hook,
                            const char *uid_hint,
                            const char *passphrase_info,
                            int prev_was_bad, int fd)
{
    write (fd, hook, strlen(hook));
    write(fd, "\n", 1);

    return 0;
}

void decrypt(char* cipher_str, char* out_str, char* passphrase)
{
        gpgme_error_t error;
        gpgme_ctx_t ctx;
        gpgme_data_t plain,cipher;
        size_t len = 0;
        char* plain_str = NULL;

        // connect to gpgme
        init_gpgme2(&ctx);

        gpgme_set_passphrase_cb(ctx, passphrase_cb2, passphrase);

        // create data containers
        gpgme_data_new_from_mem(&cipher, cipher_str,strlen(cipher_str),1);
        gpgme_data_new(&plain);

        // decrypt
        error = gpgme_op_decrypt(ctx,cipher,plain);
        if (error)
        {
                printf("gpgme_op_decrypt failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
                gpgme_release (ctx);
                return;
        }

        // release memory for data containers
        gpgme_data_release(cipher);
        plain_str = gpgme_data_release_and_get_mem(plain,&len);
        if (plain_str != NULL)
        {
                plain_str[len] = 0;
                strcpy(out_str, plain_str);
        }
        gpgme_free(plain_str);

        // close gpgme connection
        gpgme_release (ctx);
}

void verify(const char* sig_str, char* out_str)
{
        gpgme_error_t error;
        gpgme_ctx_t ctx;
        gpgme_data_t plain,sig;
        gpgme_verify_result_t result;

        if (sig_str == NULL)
        {
                printf("verify got null parameter\n");
                return;
        }

        // connect to gpgme
        init_gpgme2(&ctx);

        // create data containers
        gpgme_data_new_from_mem (&sig, sig_str,strlen(sig_str),1);
        gpgme_data_new(&plain);

        // try to verify
        error = gpgme_op_verify(ctx,sig,NULL,plain);
        if (error)
        {
                printf("gpgme_op_verify failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
                gpgme_release (ctx);
                return;
        }

        // get result
        result = gpgme_op_verify_result (ctx);
        if (result != NULL)
        {
                if (result->signatures != NULL)
                {
                        strcpy(out_str, result->signatures->fpr);
                }
        }

        // release memory for data containers
        gpgme_data_release(sig);
        gpgme_data_release(plain);
}

void encrypt(const char* plain_str, const char* fpr, char* out_str)
{
        gpgme_error_t error;
        gpgme_ctx_t ctx;
        gpgme_key_t key;
        gpgme_data_t plain,cipher;
        char* cipher_str = NULL;
        size_t len;
        gpgme_key_t key_arr[3];

        key_arr[0] = NULL;
        key_arr[1] = NULL;
        key_arr[2] = NULL;

        // connect to gpgme
        init_gpgme2(&ctx);

        // get key by fingerprint
        error = gpgme_get_key(ctx,fpr,&key,0);
        if (error || !key)
        {
                printf("gpgme_get_key failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
                gpgme_release (ctx);
                return;
        }
        key_arr[0] = key;

        // create data containers
        gpgme_data_new_from_mem (&plain, plain_str,strlen(plain_str),1);
        gpgme_data_new(&cipher);

        error = gpgme_op_encrypt (ctx, key_arr,GPGME_ENCRYPT_ALWAYS_TRUST,plain,cipher);
        if (error)
        {
                printf("gpgme_op_encrypt failed: %s %s\n",gpgme_strsource (error), gpgme_strerror (error));
                gpgme_release (ctx);
                return;
        }

        // release memory for data containers
        gpgme_data_release(plain);
        cipher_str = gpgme_data_release_and_get_mem(cipher,&len);
        if (cipher_str != NULL)
        {
                strcpy(out_str, cipher_str);
        }
        gpgme_free(cipher_str);

        // close gpgme connection
        gpgme_release(ctx);
}
