#include <stdio.h>
#include <gpgme.h>


void init_gpgme2(gpgme_ctx_t *ctx);

gpgme_error_t my_passphrase_cb(void *hook,
                               const char *uid_hint,
                               const char *passphrase_info,
                               int prev_was_bad, int fd);

void decrypt(char* cipher_str, char* out_str, char* passphrase);

void verify(const char* sig_str, char* out_str);

void encrypt(const char* plain_str, const char* fpr, char* out_str);
