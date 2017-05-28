#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <gpgme.h>
#include <locale.h>
#include "gpg.h"

void init_gpgme2(gpgme_ctx_t *ctx)
{
    gpgme_error_t err;
    setlocale(LC_ALL, ""); // set the locale
    gpgme_check_version(GPGME_PROTOCOL_OpenPGP); // initialize gpgme
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL)); // set gpgme locale
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP); // initialize gpgme

    err = gpgme_new(ctx); // initialize the context
    gpgme_set_armor(*ctx, 1);

    err = gpgme_ctx_set_engine_info(*(gpgme_ctx_t *)ctx, GPGME_PROTOCOL_OpenPGP,
                                    "/usr/bin/gpg", "~/.gnupg/");
}

gpgme_error_t my_passphrase_cb(void *hook,
                               const char *uid_hint,
                               const char *passphrase_info,
                               int prev_was_bad, int fd)
{
    write(fd, hook, strlen(hook));
    write(fd, "\n", 1);
    return 0;
}

ssize_t decrypt_verify(const char* cipherStr, size_t cipherLen,
                       const char* privKey, size_t privKeyLen, char* passphrase,
                       char** plainStrPtr, char** signerFprPtr)
{
    gpgme_error_t error;
    gpgme_ctx_t ctx;
    gpgme_data_t plain, cipher, key;
    gpgme_verify_result_t v_result;
    size_t len = 0;
    char* plainStr = NULL;

    // connect to gpgme
    init_gpgme2(&ctx);

    gpgme_set_passphrase_cb(ctx, my_passphrase_cb, passphrase);

    // create data containers
    gpgme_data_new_from_mem(&cipher, cipherStr, cipherLen, 1);
    gpgme_data_new_from_mem(&key, privKey, privKeyLen, 1);
    gpgme_data_new(&plain);

    // import key
    error = gpgme_op_import(ctx, key);
    if (error)
    {
        fprintf(stderr, "gpgme_op_import failed: %s %s\n",
                gpgme_strsource(error), gpgme_strerror(error));
        gpgme_data_release(plain);
        gpgme_data_release(cipher);
        gpgme_data_release(key);
        gpgme_release(ctx);
        return -1;
    }

    // decrypt
    error = gpgme_op_decrypt_verify(ctx, cipher, plain);
    if (error)
    {
        fprintf(stderr, "gpgme_op_decrypt_verify failed: %s %s\n",
                gpgme_strsource(error), gpgme_strerror(error));
        gpgme_data_release(plain);
        gpgme_data_release(cipher);
        gpgme_data_release(key);
        gpgme_release(ctx);
        return -1;
    }

    v_result = gpgme_op_verify_result(ctx);
    if (v_result != NULL)
    {
        if (v_result->signatures != NULL)
        {
            *signerFprPtr = strdup(v_result->signatures->fpr);
        }
    }
    else
    {
        gpgme_data_release(plain);
        gpgme_data_release(cipher);
        gpgme_data_release(key);
        gpgme_release(ctx);
        return -1;
    }

    plainStr = gpgme_data_release_and_get_mem(plain, &len);
    *plainStrPtr = malloc(len);
    memcpy(*plainStrPtr, plainStr, len);

    // release memory for data containers
    gpgme_data_release(cipher);
    gpgme_data_release(plain);
    gpgme_data_release(key);
    gpgme_free(plainStr);

    // close gpgme connection
    gpgme_release(ctx);

    return len;
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
