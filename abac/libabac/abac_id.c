
/* abac_id.c */

// include the GNU extension of asprintf
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <assert.h>
#include <err.h>
#include <time.h>

#include "libabac_common.h"
#include "abac_util.h"
#include "abac_openssl.h"

#define KEY_SUFFIX  "_private.pem"
#define CERT_SUFFIX "_ID.pem"

// ID object
//
struct _abac_id_t {
    char *keyid;
    char *cn;
    X509 *cert;
    EVP_PKEY *key;

    int refcount;
};

/**************************************************************/
/**
 * Helper function for building a ID from a cert. Used by
 * abac_id_from_*
 */
abac_id_t *_id_from_cert(X509 *cert) {
    abac_id_t *id = abac_xmalloc(sizeof(abac_id_t));
    id->cert = cert;
    id->key = NULL;

    id->keyid = abac_get_keyid(cert);
    id->cn = NULL;
    char *tmp=abac_get_cn(cert);
    if(tmp)  id->cn = abac_xstrdup(tmp);
    id->refcount = 1;
    return id;
}

/**
 * Load an ID cert from a file.
 */
abac_id_t *abac_id_from_file(char *filename) {
    libabac_init();

    FILE *fp=fopen(filename,"r");
    if(fp==NULL)
        return NULL;

    X509 *cert = abac_load_id_from_fp(fp);
    /* try to see if private key is also in here .. */
    fclose(fp);

    if (cert == NULL)
        return NULL;

    abac_id_t *id=_id_from_cert(cert);
    if(abac_id_privkey_from_file(id, filename)==ABAC_SUCCESS) {
        /* found a combo file!!! */
    }
    return id;
}

/* for some reason, there might be beginning and trailing spaces 
in pem, zap the end with \0 and skip the spaces at the start*/
char *zap_spaces(char *string)
{
   int space=0;
   int total=strlen(string);
   int i=0;
   char *ptr=string;
   while(string[i]==' ' && i<total) {
       i++;
       ptr++;
   }
   for(;i<total; i++) {
       if(string[i]==' ') {
         space++;
         string[i]='\0';
       } 
   }
   return ptr;
}

/* turn a naked pem into a real pem */
char *make_pem_from_naked_pem(char *naked_pem) {
    /* Headers and trailers with and w/o newlines (see below) */
    static char *start="-----BEGIN CERTIFICATE-----";
    static char *startnl="-----BEGIN CERTIFICATE-----\n";
    static char *end="-----END CERTIFICATE-----";
    static char *endnl="\n-----END CERTIFICATE-----";
    char *s = NULL;
    char *e = NULL;
    char *pem=NULL;
    char *ptr=zap_spaces(naked_pem);
    int slen = strlen(ptr);

    /*
     * The -----BEGIN...  and -----END need to be followed by newlines and the
     * Base64 that gets passed in here may or may not have newlines in the
     * right places.  when we add a header or trailer, pick one that makes the
     * newlines right.
     */
    if (ptr[0] == '\n') s = start;
    else s = startnl;

    if (ptr[slen-1] == '\n') e = end;
    else e = endnl;

   if ( asprintf(&pem,"%s%s%s",s,ptr,e) < 0 ) return NULL;
    return pem;
}

/* build a x509 out of a named pem, extract the sha1 value and
   free up everything */
void abac_get_sha_from_nake_pem(char *naked_pem, char **sha1) {
    abac_chunk_t chunk;
    /* make a copy of this naked_pem */
    char *new_naked_pem=abac_xstrdup(naked_pem);
    char *pem=make_pem_from_naked_pem(new_naked_pem);
    chunk.ptr = (unsigned char *) pem;
    chunk.len = strlen(pem);
    X509 *cert=abac_load_id_from_chunk(chunk.ptr,chunk.len);
    *sha1=NULL;
    if(cert) {
        *sha1 = abac_get_keyid(cert);
        } else {
            *sha1=NULL;
            fprintf(stderr,"can not make cert from pem blob!!\n");
    }
    X509_free(cert);
    free(new_naked_pem);
    abac_chunk_free(&chunk);
}

/**
 * Load an ID cert from a chunk.
 */
abac_id_t *abac_id_from_chunk(abac_chunk_t chunk) {
    libabac_init();
    X509 *cert= abac_load_id_from_chunk(chunk.ptr, chunk.len);

    if (cert == NULL)
        return NULL;

    abac_id_t *id=_id_from_cert(cert);
    if(abac_id_privkey_from_chunk(id, chunk)==ABAC_SUCCESS) {
        /* found a combo chunk */
    }
    return id;
}

static EVP_PKEY *_load_privkey_from_file(char *filename)
{
    FILE *fp=fopen(filename,"r");
    if(fp==NULL) return NULL;
    EVP_PKEY *key=abac_load_privkey_from_fp(fp);
    fclose(fp);
    return key;
}

/**
 * Load private key for a cert.
 */
int abac_id_privkey_from_file(abac_id_t *id, char *filename) {
    assert(id != NULL);

    EVP_PKEY *key=_load_privkey_from_file(filename);
    if (key == NULL) return ABAC_FAILURE;

/* needs to make sure that the key matches up with the id */
    /* extract the pub key from the id */
    EVP_PKEY *pubkey=extract_pubkey_from_cert(id->cert);
    /* cmp will just compare the pub key part of the key to see
       if they are the same */
    if(!EVP_PKEY_cmp(pubkey, key)) {
        fprintf(stderr,"wrong private key for the cert!!\n");
        return ABAC_FAILURE;
    }

    /* free up the extracted pukey */
    EVP_PKEY_free(pubkey);

    id->key = key;
    return ABAC_SUCCESS;
}

int abac_id_privkey_from_chunk(abac_id_t *id, abac_chunk_t chunk) {
    assert(id != NULL);

    EVP_PKEY *key=abac_load_privkey_from_chunk(chunk.ptr, chunk.len);
    if (key == NULL) return ABAC_FAILURE;

/* needs to make sure that the key matches up with the id */
    /* extract the pub key from the id */
    EVP_PKEY *pubkey=extract_pubkey_from_cert(id->cert);
    /* cmp will just compare the pub key part of the key to see
       if they are the same */
    if(!EVP_PKEY_cmp(pubkey, key)) {
        fprintf(stderr,"wrong private key for the cert!!\n");
        return ABAC_FAILURE;
    }

    /* free up the extracted pukey */
    EVP_PKEY_free(pubkey);

    id->key = key;
    return ABAC_SUCCESS;
}

/* pass a privkey from one id to another, very special case for
   preloading issuer id when attribute is being loaded and when
   there is an exising principal credential in the hashlist but
   did not have its privkey setup yet */
int abac_id_pass_privkey_from_id(abac_id_t *to_id, abac_id_t *from_id) {
    EVP_PKEY *key=from_id->key;
    from_id->key=NULL; /* reset the one in from so it does not get freed */
    if (key==NULL) return ABAC_FAILURE;

/* needs to make sure that the key matches up with the id */
    /* extract the pub key from the id */
    EVP_PKEY *pubkey=extract_pubkey_from_cert(to_id->cert);
    /* cmp will just compare the pub key part of the key to see
       if they are the same */
    if(!EVP_PKEY_cmp(pubkey, key)) {
        fprintf(stderr,"wrong private key for the cert!!\n");
        return ABAC_FAILURE;
    }

    /* free up the extracted pukey */
    EVP_PKEY_free(pubkey);

    to_id->key = key;
    return ABAC_SUCCESS;
}

/**
 * Generate an ID with the specified CN and validity.
 *
 * validity is measured in seconds (as of 0.2.0)
 */
int abac_id_generate(abac_id_t **ret, char *cn, long validity) {
    libabac_init();
    if (cn == NULL || !abac_clean_name(cn))
        return ABAC_GENERATE_INVALID_CN;

    if (validity < 0)
        return ABAC_GENERATE_INVALID_VALIDITY;

    abac_id_t *id = abac_xmalloc(sizeof(abac_id_t));

    id->cn = abac_xstrdup(cn);
    id->key = abac_generate_key();
    id->cert = abac_generate_cert(id->key, cn, validity);
    id->keyid = abac_get_keyid(id->cert);

    id->refcount = 1;

    *ret = id;
    return ABAC_SUCCESS;
}

/**
 * Generate an ID with the specified CN and validity.
 *
 * validity is measured in seconds (as of 0.2.0)
 */
int abac_id_generate_with_key(abac_id_t **ret, char *cn, long validity, char *keyfile) {
    libabac_init();
    if (cn == NULL || !abac_clean_name(cn))
        return ABAC_GENERATE_INVALID_CN;

    if (validity < 0)
        return ABAC_GENERATE_INVALID_VALIDITY;

    abac_id_t *id = abac_xmalloc(sizeof(abac_id_t));

    id->cn = abac_xstrdup(cn);
    id->key = _load_privkey_from_file(keyfile);
    id->cert = abac_generate_cert(id->key, cn, validity);
    id->keyid = abac_get_keyid(id->cert);
    id->refcount = 1;

    *ret = id;
    return ABAC_SUCCESS;
}

char *abac_id_keyid(abac_id_t *id) {
    if(id) return id->keyid;
        return NULL;
}

char *abac_id_cn(abac_id_t *id) {
    if(id) return id->cn;
        return NULL;
}

/**
 * Get the issuer of an ID cert.
 * Returns a malloc'd string that must be free'd.
 */
char *abac_id_issuer(abac_id_t *id) {
    if(id) return abac_get_issuer(id->cert);
        else return NULL;
}

/**
 * Gets the subject DN of an ID cert.
 * Returns a malloc'd string that must be free'd.
 */
char *abac_id_subject(abac_id_t *id) {
    if(id) return abac_get_subject(id->cert);
        else return NULL;
}

/**
 * Get the validity period.
 */
int abac_id_validity(abac_id_t *id,struct tm *not_before,struct tm *not_after) {
    assert(id);
    if(abac_check_validity(id->cert, not_before, not_after)==0)
        return ABAC_SUCCESS;
    return ABAC_FAILURE;
}

X509 *abac_id_cert(abac_id_t *id) {
    assert(id);
    return id->cert;
}

// get the private key from the ID
// will return NULL if no key has been loaded
EVP_PKEY *abac_id_privkey(abac_id_t *id) {
    assert(id);
    return id->key;
}

int abac_id_has_privkey(abac_id_t *id) {
    if(id && (id->key !=NULL))
        return 1;
    return 0;
}

// see if keyid is the same as id's
int abac_id_has_keyid(abac_id_t *id, char *keyid)
{
    assert(id); assert(keyid);
    if(strcmp(id->keyid, keyid) == 0)
        return 1;
    return 0;
}

/*
   return a chunk with both id and key info,
   err if missing privkey
*/
int abac_id_PEM(abac_id_t *id, abac_chunk_t *chunk) {
    if(id==NULL)
        return ABAC_CERT_MISSING_ISSUER;
    if(id->key == NULL)
        return ABAC_CERT_SIGNER_NOKEY;

    unsigned char *kptr=NULL;
    unsigned char *ptr=abac_string_cert(id->cert);
    if(id->key)
        kptr=abac_string_privkey(id->key);
    
    char *tmp=NULL;
    if(kptr)  {
        int rc = asprintf(&tmp,"%s%s", ptr,kptr);
        free(ptr);
        free(kptr);
	if (rc < 0 ) return -1;
        } else {
            tmp=(char *)ptr;
    }

    chunk->ptr=(unsigned char *)tmp;
    chunk->len=strlen(tmp);

    return ABAC_CERT_SUCCESS;
}

abac_chunk_t abac_id_in_PEM(abac_id_t *id) {
    assert(id);
    unsigned char *ptr=abac_string_cert(id->cert);
    int len=0;
    if(ptr)
        len=strlen((char *)ptr);
    abac_chunk_t ret = { ptr, len};
    return ret;
}


int abac_id_still_valid(abac_id_t *id) {
    assert(id);
    return abac_still_valid(id->cert);
}

/**
 * Get the default filename for the cert. Value must be freed by caller.
 */
char *abac_id_cert_filename(abac_id_t *id) {
    assert(id != NULL);
    assert(id->cn != NULL);

    // malloc the filename
    int len = strlen(id->cn) + strlen(CERT_SUFFIX) + 1;
    char *filename = abac_xmalloc(len);
    sprintf(filename, "%s" CERT_SUFFIX, id->cn);

    return filename;
}

/**
 * Write the ID cert to an open file pointer.
 * pem format
 */
int abac_id_write_cert(abac_id_t *id, FILE *out) {
    assert(id != NULL);

    int ret=abac_write_id_to_fp(id->cert, out);
    if(ret) return ABAC_FAILURE; 
    return ABAC_SUCCESS;
}

/**
 * Default private key filename. Value must be freed by caller.
 */
char *abac_id_privkey_filename(abac_id_t *id) {
    assert(id != NULL);
    assert(id->cn != NULL);

    // malloc the filename
    int len = strlen(id->cn) + strlen(KEY_SUFFIX) + 1;
    char *filename = abac_xmalloc(len);
    sprintf(filename, "%s" KEY_SUFFIX, id->cn);

    return filename;
}

/**
 * Write the private key to a file.
 * Returns false if there's no private key loaded
 * PEM format
 */
int abac_id_write_privkey(abac_id_t *id, FILE *out) {
    assert(id != NULL);
    if (id->key == NULL)
        return ABAC_FAILURE;

    int ret=abac_write_privkey_to_fp(id->key, out);
    if (ret)
        return ABAC_FAILURE;

    return ABAC_SUCCESS;
}

/**
 * Get a abac_chunk representing the id cert.
 * caller is responsible to free up the chunk after use
 */
abac_chunk_t abac_id_cert_chunk(abac_id_t *id) {

    assert(id); assert(id->cert);
    unsigned char *ptr=abac_string_cert(id->cert);
    int len=0;
    if(ptr) len=strlen( (char *)ptr);

    abac_chunk_t ret = { ptr, len };
    return ret;
}

/**
 * Get a abac_chunk representing the privkey cert.
 */
abac_chunk_t abac_id_privkey_chunk(abac_id_t *id) {

    assert(id); assert(id->key);
    unsigned char *ptr=abac_string_privkey(id->key);
    int len=0;
    if(ptr) len=strlen( (char *)ptr);

    abac_chunk_t ret = { ptr, len };
    return ret;
}


/**
 * Copy a ID. Actually just increases its reference count.
 */
abac_id_t *abac_id_dup(abac_id_t *id) {
    assert(id);
    ++id->refcount;
    return id;
}

void abac_id_free(abac_id_t *id) {
    if (id == NULL)
        return;

    --id->refcount;
    if (id->refcount > 0)
        return;

    // free once the reference count reaches 0
    X509_free(id->cert);
    EVP_PKEY_free(id->key);

    free(id->keyid);
    if(id->cn) free(id->cn);

    free(id);
}

