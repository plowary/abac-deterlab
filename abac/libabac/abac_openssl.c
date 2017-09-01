
/* abac_openssl.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>

#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


#ifdef HAVE_READPASSPHRASE
# include <readpassphrase.h>
#else
# include "compat/readpassphrase.h"
#endif

int _potato_cb(char *buf, int sz, int rwflag, void *u);

/***********************************************************************/
int init_openssl() {
    OpenSSL_add_all_algorithms();
    return 0;
}

int deinit_openssl() {
    CRYPTO_cleanup_all_ex_data();
    return 0;
}

/* int RAND_bytes(unsigned char *buf, int num); */
unsigned char *abac_generate_serial() {
    unsigned char *serial=(unsigned char *) malloc(sizeof(unsigned char)*8);

    memset(serial, '\0', 8);

    if(!RAND_bytes(serial,8)) {
        fprintf(stderr,"RAT, RAN^D out of seeds!!!\n");
        assert(0);
    }
    // zap leading 0's
    while (serial[0] == 0)
        RAND_bytes(&serial[0],1);

    RAND_cleanup();
    return serial;
}


static BIGNUM *_make_bn_from_string(unsigned char *str)
{
    assert(str);
    BIGNUM *tmp;
    tmp=BN_bin2bn(str,8,NULL);
/* BN_print_fp(stderr,tmp); */
    int n=BN_num_bytes(tmp);
    if(n) return tmp;
        return NULL;
}

unsigned char *_encode_m64(unsigned char *orig_ptr, int orig_len)
{
    BIO *mbio,*b64bio,*bio;

    unsigned char *m64_ptr=NULL;
    int m64_len=0;

    unsigned char *ptr=NULL;

    if(orig_len==0) return NULL;

    /*bio pointing at b64->mem, the base64 bio encodes on
      write and decodes on read */
    mbio=BIO_new(BIO_s_mem());
    b64bio=BIO_new(BIO_f_base64());
    bio=BIO_push(b64bio,mbio);

    BIO_write(bio,orig_ptr,orig_len);

    /* We need to 'flush' things to push out the encoding of the
    * last few bytes.  There is special encoding if it is not a
    * multiple of 3
    */
    (void) BIO_flush(bio);

    /* pointer to the data and the number of elements. */
    m64_len=(int)BIO_ctrl(mbio,BIO_CTRL_INFO,0,ptr);

    if(m64_len!=0) {
       m64_ptr=malloc(m64_len+1);
       if(m64_ptr) {
           strcpy((char *)m64_ptr, (char *)ptr);
           } else { 
               fprintf(stderr,"ERROR: malloc failed\n");
       }
    }

    /* This call will walk the chain freeing all the BIOs */
    BIO_free_all(bio);
    return m64_ptr;
}

unsigned char *_decode_m64(unsigned char *m64_ptr, int m64_len)
{
    unsigned char *orig_ptr=NULL;
    int orig_len=0;

    BIO *b64bio, *mbio, *bio;
    char *ptr=NULL;

    if(m64_len==0) return NULL;

    ptr = (char *)malloc(sizeof(char)*m64_len);
    memset(ptr, '\0', m64_len);

    b64bio = BIO_new(BIO_f_base64());
    mbio = BIO_new_mem_buf(m64_ptr, m64_len);
    bio = BIO_push(b64bio, mbio);

    orig_len=BIO_read(bio, ptr, m64_len);
    
    if(orig_len) {
        orig_ptr=malloc(orig_len+1);
        if(orig_ptr)
            strcpy((char *)orig_ptr, ptr);
            else fprintf(stderr,"ERROR: malloc failed..\n");
    }

    BIO_free_all(bio);
    return orig_ptr;
}

/*** not used
static char *_read_blob_from_file(char *fname, int *len)
{
    struct stat sb;
    char *dptr=NULL;

    int fd = open(fname, O_RDONLY);
    if (fd == -1) { return NULL; }
    if(stat(fname, &sb) == -1) {
        close(fd);
        return NULL;
    }
    dptr= (char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if(dptr == MAP_FAILED) {
        return NULL;
    }
    *len=sb.st_size;
    return dptr;
}
***/

/* Read ID in PEM */
X509 *abac_load_id_from_fp(FILE *fp)
{
    X509 *cert=PEM_read_X509(fp,NULL,NULL,NULL);
    return cert;
}

X509 *abac_load_id_from_chunk(unsigned char *chunk_ptr, int chunk_len)
{
    X509 *n509=NULL;
    BIO *mbio=BIO_new(BIO_s_mem());

    BIO_write(mbio,chunk_ptr,chunk_len);
    (void) BIO_flush(mbio);

    if( !PEM_read_bio_X509(mbio,&n509,0,NULL)) {
        return NULL;
    } 

    BIO_free_all(mbio);

    return n509;
}

int abac_write_id_to_fp(X509 *cert, FILE *fp)
{
    assert(cert);

    if(!PEM_write_X509(fp,cert)) {
        return 1;
    }
    return 0;
}

/* make stringfy a private key PEM struct */
unsigned char *abac_string_privkey(EVP_PKEY *key)
{
    unsigned char *ptr=NULL;
    unsigned char *tmp=NULL;

    assert(key);

    BIO *mbio=BIO_new(BIO_s_mem());
    /* PEM_write_PrivateKey(fp,key,NULL,NULL,0,_potato_cb, "privateKey to file"); */
    PEM_write_bio_PrivateKey(mbio,key,NULL,NULL,0,_potato_cb,"stringify privateKey");
    (void) BIO_flush(mbio);
    int len=(int)BIO_ctrl(mbio,BIO_CTRL_INFO,0,tmp);

    if(len) {
        ptr=(unsigned char *)malloc(sizeof(unsigned char *)*(len+1));
        int ret=BIO_read(mbio, (void *)ptr, len);
        if(ret==0)
            fprintf(stderr," abac_string_privkey failed!!\n");
        ptr[len]='\0';
    }
    BIO_free_all(mbio);
    return ptr;
}

/* make stringfy a x509 PEM struct */
unsigned char *abac_string_cert(X509 *cert) {
    unsigned char *ptr=NULL;
    unsigned char *tmp=NULL;

    assert(cert);

    BIO *mbio=BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio,cert);
    (void) BIO_flush(mbio);
    int len=(int)BIO_ctrl(mbio,BIO_CTRL_INFO,0,tmp);

    if(len) {
        ptr=(unsigned char *)malloc(sizeof(unsigned char *)*(len+1));
        int ret=BIO_read(mbio, (void *)ptr, len);
        if(ret==0)
            fprintf(stderr," abac_string_cert failed!!\n");
        ptr[len]='\0';
    }
    
    BIO_free_all(mbio);
    return ptr;
}


/* not used, sign data with privkey  
static int _sign_with_privkey(EVP_PKEY *privkey, char *data,
unsigned char* signed_buf)
{
  int err;
  unsigned int signed_len;
  EVP_MD_CTX     md_ctx;

  EVP_SignInit   (&md_ctx, EVP_md5());
  EVP_SignUpdate (&md_ctx, data, strlen(data));
  signed_len = sizeof(signed_buf);
  err = EVP_SignFinal (&md_ctx,
                       signed_buf,
                       &signed_len,
                       privkey);
  if (err != 1) {
      return 1;
  }
  return 0;
}
**/

/* nost used, verify the signature.. 
static int _verify_with_pubkey(EVP_PKEY *pubkey, char *data,
unsigned char* signed_buf )
{
  int err;
  int signed_len;
  EVP_MD_CTX     md_ctx;

  EVP_VerifyInit   (&md_ctx, EVP_sha1());
  EVP_VerifyUpdate (&md_ctx, data, strlen((char*)data));
  signed_len=sizeof(signed_buf);
  err = EVP_VerifyFinal (&md_ctx,
                         signed_buf,
                         signed_len,
                         pubkey);

  if (err != 1) {
        return 1;
  }
  fprintf(stderr, "Signature Verified Ok.\n");
  return 0;
}
***/


#define PWLEN 128
/* EVP_PKEY *PEM_read_PrivateKey(FILE *,EVP_PKEY **,pem_cb *,void *) */
int _potato_cb(char *buf, int sz, int rwflag, void *u)
{
   int len;
   char *prompt=NULL;
   int rc;
   if(u)
       rc=asprintf(&prompt,"Enter passphrase for %s:", (char *)u);
       else rc=asprintf(&prompt,"Enter passphrase :");
    if ( rc == -1 ) return 0;
   char *secret = malloc(PWLEN);
   memset(secret, '\0', PWLEN);
   if(!secret) {
        perror("malloc()");
        free(prompt);
        return 0;
   }
   if (readpassphrase( prompt, secret, PWLEN, RPP_ECHO_OFF) == NULL) {
       perror("readpassphrase()");
       memset(secret, '\0', PWLEN);
       len=0;
       } else {
           len=strlen(secret);
           memcpy(buf, secret, len);
           memset(secret, '\0', len);
   }
   free(secret);
   free(prompt);
   return len;
}

EVP_PKEY *abac_load_privkey_from_chunk(unsigned char *chunk_ptr, int chunk_len)
{
    EVP_PKEY *nkey=NULL;
    BIO *mbio=BIO_new(BIO_s_mem());

    BIO_write(mbio,chunk_ptr,chunk_len);
    (void) BIO_flush(mbio);

    PEM_read_bio_PrivateKey(mbio,&nkey,NULL,NULL);

    BIO_free_all(mbio);

    if (nkey == NULL) {
        return NULL;
    }
    return nkey;
}

EVP_PKEY *abac_load_privkey_from_fp(FILE *fp)
{
    assert(fp);

    EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, _potato_cb, "privateKey from file");
    return privkey;
}

/* not adding passphrase */
int abac_write_privkey_to_fp(EVP_PKEY *key, FILE *fp) {
    assert(key);

    if(!PEM_write_PrivateKey(fp,key,NULL,NULL,0,NULL, NULL)) {
        return 1;
    }
    return 0;
}

/* adding passphrase */
int abac_write_encrypt_privkey_to_fp(EVP_PKEY *key, FILE *fp) {
    assert(key);

    if(!PEM_write_PrivateKey(fp,key,NULL,NULL,0,_potato_cb, "privateKey to file")) {
        return 1;
    }
    return 0;
}

EVP_PKEY *extract_pubkey_from_cert(X509 *cert)
{
    EVP_PKEY *pubkey=X509_get_pubkey(cert);
    return pubkey;
}


/** not used,
static void _callback(int p, int n, void *arg)
{
    char c='B';

    if (p == 0) c='.';
    if (p == 1) c='+';
    if (p == 2) c='*';
    if (p == 3) c='\n';
    fputc(c,stderr);
}
***/

/* 
RSA *RSA_generate_key(int num, unsigned long e,
   void (*callback)(int,int,void *), void *cb_arg);
The exponent is an odd number, typically 3, 17 or 65537
*/
EVP_PKEY* abac_generate_key()
{
    EVP_PKEY *pk=NULL;
    int keysize=2048;

    if((pk=EVP_PKEY_new()) == NULL){
        return NULL;
    }

//    RSA *rsa=RSA_generate_key(keysize,RSA_F4,_callback,NULL); 
    RSA *rsa=RSA_generate_key(keysize,RSA_F4,NULL,NULL); 
    if (!EVP_PKEY_assign_RSA(pk,rsa)) {
        return NULL;
    }
    rsa=NULL;

    return pk;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
static int _add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}


/**
 * Generate ID certificate.
 *
 * validity is measured in seconds (as of 0.2.0)
 */
X509 *abac_generate_cert(EVP_PKEY *pkey, char *cn, long validity) {

    /* must have a privkey before generating an ID cert */
    assert(pkey);
    X509 *cert=NULL;
    unsigned char *serial=abac_generate_serial();
    BIGNUM *bn=_make_bn_from_string(serial);

    if((cert=X509_new()) == NULL)
            goto error;

    if(validity == 0) validity=(long)(60*60*24*(365));

    X509_set_version(cert,2);

    BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
    /* this is prone to problem with very big days on 32 bit machines,
       In newer openssl, can migrate to X509_time_adj_ex */ 
    X509_gmtime_adj(X509_get_notBefore(cert),0);
    X509_gmtime_adj(X509_get_notAfter(cert),validity);
    X509_set_pubkey(cert,pkey);

    X509_NAME *name=X509_get_subject_name(cert);

    if(!name) goto error;

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     */
    if(!(X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0)))
        goto error; // fail to add cn to cert 

    /* Self signed, set the issuer name to be the same as the subject. */
    if(!(X509_set_issuer_name(cert,name)))
        goto error; // fail to set issuer name on cert 

    /* Add various extensions: standard extensions */
    if(!(_add_ext(cert, NID_basic_constraints, "critical,CA:TRUE")))
        goto error; // fail to set basic constraint
    if(!(_add_ext(cert, NID_key_usage, "critical,keyCertSign,cRLSign")))
        goto error; // fail to set key usage
    if(!(_add_ext(cert, NID_subject_key_identifier, "hash")))
        goto error; // fail to set subject key identifier
    if(!(_add_ext(cert, NID_authority_key_identifier, "keyid:always")))
        goto error; // fail to set authority key identifier (self-signing)

    /* make sure it is signed */
    if (!X509_sign(cert,pkey,EVP_sha1()))
        goto error;

    if(serial) free(serial);
    if(bn) BN_free(bn);
    return cert;

error:
    if(cert) X509_free(cert);
    if(serial) free(serial);
    if(bn) BN_free(bn);
    return NULL;
}

/*** not used,
static char *_time_in_string(ASN1_TIME *tm)
{
    char *ptr=NULL;
    BIO *mbio=BIO_new(BIO_s_mem());
    ASN1_TIME_print(mbio, tm);
    BIO_flush(mbio);
    int len=BIO_number_written(mbio);
    ptr=(char *) malloc(sizeof(char *)*(len+1));
    int ret=BIO_read(mbio, (void *)ptr, len);

    BIO_free_all(mbio);
    if(ret)
        return ptr; 
        else return NULL;
} 
***/


/* atime->data, YYmmddHHMMSS or YYYYmmddHHMMSSZZ 
 *  V_ASN1_UTCTIME, V_ASN1_GENERALIZEDTIME 
 */
static int _convert_time(struct tm *ttime, ASN1_TIME *atime) {
    assert(atime); assert(atime->data);

    int type=atime->type;
    int len=strlen((char *)atime->data);
    if(len==0) return 0;

    char *astring=strndup((char *)atime->data,len);

    /* setting ttime structure */
    if (type == V_ASN1_UTCTIME) {
           strptime(astring, "%y%m%d%H%M%S", ttime);
        } else {
        if (type == V_ASN1_GENERALIZEDTIME)
           strptime(astring, "%Y%m%d%H%M%S", ttime);
           else fprintf(stderr,"ERROR,.. unknown type in ASN1_TIME struct\n");
    }

    return 1;
}

/* check whether the cert is still valid or not and also extract what its 
   not_before and not_after field, 0 is okay, 1 is not */
int abac_check_validity(X509 *cert, struct tm *not_before, struct tm *not_after) {
    assert(cert);

    int valid=0;
    int ret=0;
    memset(not_before, 0, sizeof(struct tm));
    memset(not_after, 0, sizeof(struct tm));
    ASN1_TIME *notAfter= X509_get_notAfter(cert);
    ASN1_TIME *notBefore=X509_get_notBefore(cert);

    ret=_convert_time(not_before, notBefore);
    if(ret==0) return 1;
    ret=_convert_time(not_after, notAfter);
    if(ret==0) return 1;

    if((X509_cmp_current_time(notBefore) >=0) ||
                  (X509_cmp_current_time(notAfter) <=0) )
      valid=1;

    if(valid) return 0;
       else return 1;
}

/* check if cert is still valid at current time, 1 for yes, 0 for no*/
int abac_still_valid(X509 *cert)
{
    ASN1_TIME *notAfter= X509_get_notAfter(cert);
    ASN1_TIME *notBefore=X509_get_notBefore(cert);
    if(0) {
        fprintf(stderr,"((X509_cmp_current_time(notBefore) is %d\n", 
                                  X509_cmp_current_time(notBefore));
        fprintf(stderr,"((X509_cmp_current_time(notAfter) is %d\n", 
                                  X509_cmp_current_time(notAfter));
    }
    if((X509_cmp_current_time(notBefore) >=0) ||
                   (X509_cmp_current_time(notAfter) <=0) )
      return 0;
    return 1;
}

char *abac_get_cn(X509 *cert)
{
   X509_NAME *nptr=X509_get_subject_name (cert);
   int pos=X509_NAME_get_index_by_NID(nptr, NID_commonName,-1);
   X509_NAME_ENTRY *ent=X509_NAME_get_entry(nptr,pos); 
   ASN1_STRING *adata=X509_NAME_ENTRY_get_data(ent);
   unsigned char *val=ASN1_STRING_data(adata);
   return (char *) val;
}

char *abac_get_serial(X509 *cert)
{
   char *ret=NULL;
   ASN1_INTEGER *num=X509_get_serialNumber(cert);
   BIGNUM *bnser=ASN1_INTEGER_to_BN(num,NULL);
   int n=BN_num_bytes(bnser);
   unsigned char buf[n];
   int b=BN_bn2bin(bnser,buf);
   if(n!=0 && b!=0)
       ret=strndup((char *)buf,n);
   return ret;
}

char *abac_get_subject(X509 *cert) 
{
   char *ptr=X509_NAME_oneline(X509_get_subject_name(cert),0,0);
   return ptr;
}

char *abac_get_issuer(X509 *cert) 
{   
   char *ptr=X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
   return ptr;
}

//  success: malloc'd calculated SHA1 of the key (as per RFC3280)
//  fail: NULL
unsigned char *abac_get_keyid(X509 *cert)
{
    char digest[SHA_DIGEST_LENGTH]; /* SSL computed key digest */
    /* ASCII (UTF-8 compatible) text for the digest */
    unsigned char *sha=(unsigned char *) malloc(2*SHA_DIGEST_LENGTH+1);
    int i;  /* Scratch */

    if ( !sha) return NULL;

    if ( !X509_pubkey_digest(cert, EVP_sha1(), (unsigned char *)digest, NULL)) {
	free(sha);
	return NULL;
    }

    /* Translate to ASCII */
    for ( i = 0; i < SHA_DIGEST_LENGTH; i++)
	snprintf((char *) sha+2*i, 3, "%02x", digest[i] & 0xff);
    sha[2*SHA_DIGEST_LENGTH] = '\0';

    return sha;
}
