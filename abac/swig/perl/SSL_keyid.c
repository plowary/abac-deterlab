#include <stdlib.h>

#include <openssl/x509.h>

char *SSL_keyid(void *ptr) {
    int i;
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    char *hash;
    X509 *x = (X509 *)ptr;

    X509_pubkey_digest(x, EVP_sha1(), sha1_hash, NULL);

    hash = malloc(SHA_DIGEST_LENGTH * 2 + 1);
    for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
        sprintf(&hash[2*i], "%02x", sha1_hash[i]);

    return hash;
}
