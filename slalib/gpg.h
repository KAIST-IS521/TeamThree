#include <stdio.h>
#include <gpgme.h>


void init_gpgme2(gpgme_ctx_t *ctx);

gpgme_error_t my_passphrase_cb(void *hook,
                               const char *uid_hint,
                               const char *passphrase_info,
                               int prev_was_bad, int fd);

ssize_t decrypt_verify(const char* cipherStr, size_t cipherLen,
                       const char* privKey, size_t privKeyLen, char* passphrase,
                       char** plainStrPtr, char** signerFprPtr);

ssize_t encrypt(const char* plainStr, size_t plainStrLen,
                const char* recipFpr, char** cipherStrPtr);
