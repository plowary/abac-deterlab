/* abac_openssl.h */

#ifndef __ABAC_OPENSSL_H__
#define __ABAC_OPENSSL_H__

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* ID */
EVP_PKEY* abac_generate_key();
X509 *abac_generate_cert(EVP_PKEY *, char*, long);

// 8 bytes
unsigned char *abac_generate_serial();

// 
int init_openssl();
int deinit_openssl();

X509 *abac_load_id_from_fp(FILE *);
EVP_PKEY *abac_load_privkey_from_fp(FILE *);
EVP_PKEY *abac_load_privkey_from_chunk(unsigned char *, int);
X509 *abac_load_id_from_chunk(unsigned char *, int);
int abac_write_id_to_fp(X509 *cert, FILE *fp);
int abac_write_privkey_to_fp(EVP_PKEY *key, FILE *fp);

EVP_PKEY *extract_pubkey_from_cert(X509 *);

unsigned char *abac_string_cert(X509 *);
EVP_PKEY *extract_pubkey_from_cert(X509 *);
unsigned char *abac_string_privkey(EVP_PKEY *);

char *abac_get_serial(X509 *);
char *abac_get_cn(X509 *);
char *abac_get_subject(X509 *); 
char *abac_get_issuer(X509 *);

// sha of cert
char *abac_get_keyid(X509 *);

int abac_check_validity(X509 *, struct tm *, struct tm *);
int abac_still_valid(X509 *);

#endif /*__ABAC_OPENSSL_H__ */
