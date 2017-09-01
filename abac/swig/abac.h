#ifndef __ABAC_H__
#define __ABAC_H__

#include <time.h>  // for struct tm 
#include <stdio.h> // for FILE

typedef struct _abac_context_t abac_context_t;
typedef struct _abac_credential_t abac_credential_t;
typedef struct _abac_id_cert_t abac_id_cert_t;
typedef struct _abac_role_t abac_role_t;

typedef struct _abac_id_t abac_id_t;
typedef struct _abac_attribute_t abac_attribute_t;

typedef struct _abac_list_t ABAC_LIST_T;

#ifndef __ABAC_CHUNK_T__
#define __ABAC_CHUNK_T__
/* The len is the number of string bytes contained in the chunk,
 * neglecting the trainling 0.  The whole chunk thing should probably
 * be deprecated. -- tvf */
typedef struct _abac_chunk_t {
    unsigned char *ptr;
    int len;
} abac_chunk_t;

void abac_chunk_free(abac_chunk_t *);
#endif /* __ABAC_CHUNK_T__ */

typedef struct abac_keyid_mapping_t abac_keyid_mapping_t;
typedef struct abac_keyid_map_t abac_keyid_map_t;

/*
 * ABAC functions, operating on an ABAC context.
 */
abac_context_t *abac_context_new(void);
abac_context_t *abac_context_dup(abac_context_t *ctx);
void abac_context_free(abac_context_t *ctx);


/* see the bottom of the file for possible return codes */
int abac_context_load_id_file(abac_context_t *ctx, char *filename);
int abac_context_load_id_chunk(abac_context_t *ctx, abac_chunk_t cert);
int abac_context_load_id_id(abac_context_t *ctx, abac_id_t *cert);
int abac_context_load_attribute_file(abac_context_t *ctx, char *filename);
int abac_context_load_attribute_chunk(abac_context_t *ctx, abac_chunk_t cert);

/* load an entire directory full of certs */
void abac_context_load_directory(abac_context_t *ctx, char *path);

/* abac query, returns a NULL-terminated array of credentials on success, NULL on fail */
abac_credential_t **abac_context_query(abac_context_t *ctx, char *role, char *principal, int *success);

/* get all the credentials from the context, returns a NULL-terminated array of credentials */
abac_credential_t **abac_context_credentials(abac_context_t *ctx);

/* get all the principals from the context, returns a NULL-terminated array of credentials */
abac_id_cert_t **abac_context_principals(abac_context_t *ctx);
void abac_context_id_credentials_free(abac_id_cert_t **);

/* use this to free the results of either of the previous two functions */
void abac_context_credentials_free(abac_credential_t **credentials);
/* Used to pretty print */
int abac_context_set_nickname(abac_context_t *ctxt, char *key, char*nick);
char *abac_context_expand_key(abac_context_t *ctxt, char *s );
char *abac_context_expand_nickname(abac_context_t *ctxt, char *s );
abac_keyid_map_t *abac_context_get_keyid_map(abac_context_t *ctxt);

/*
 * Operations on credentials
 */
abac_role_t *abac_credential_head(abac_credential_t *cred);
abac_role_t *abac_credential_tail(abac_credential_t *cred);
abac_chunk_t abac_credential_attribute_cert(abac_credential_t *cred);
abac_chunk_t abac_credential_issuer_cert(abac_credential_t *cred);

abac_credential_t *abac_credential_dup(abac_credential_t *cred);
void abac_credential_free(abac_credential_t *cred);
char *abac_id_cert_keyid(abac_id_cert_t *);
char *abac_id_cert_cn(abac_id_cert_t *);

/*
 * Operations on roles.
 */
abac_role_t *abac_role_principal_new(char *principal);
abac_role_t *abac_role_role_new(char *principal, char *abac_role_name);
abac_role_t *abac_role_linking_new(char *principal, char *linked_role, char *abac_role_name);

void abac_role_free(abac_role_t *role);

abac_role_t *abac_role_from_string(char *string);
abac_role_t *abac_role_dup(abac_role_t *role);

int abac_role_is_principal(abac_role_t *role);
int abac_role_is_role(abac_role_t *role);
int abac_role_is_linking(abac_role_t *role);
int abac_role_is_intersection(abac_role_t *role);

char *abac_role_string(abac_role_t *role);
char *abac_role_short_string(abac_role_t *role, abac_context_t *ctxt);
char *abac_role_linked_role(abac_role_t *role);
char *abac_role_linking_role(abac_role_t *role);
char *abac_role_role_name(abac_role_t *role);
char *abac_role_principal(abac_role_t *role);

char *abac_role_attr_key(abac_role_t *head_role, abac_role_t *tail_role);

/*
 * Operations on ID
 */
// create an ID from an X.509 certificate
abac_id_t *abac_id_from_file(char *);

// create an ID from a X.509 certificate PEM chunk
abac_id_t *abac_id_from_chunk(abac_chunk_t chunk);

// load an X.509 private key from a file
int abac_id_privkey_from_file(abac_id_t *id, char *filename);

// load an X.509 private key from a chunk
int abac_id_privkey_from_chunk(abac_id_t *id, abac_chunk_t chunk);

// generate an ID
// returns one of ABAC_SUCCESS or ABAC_GENERATE_* (see top)
int abac_id_generate(abac_id_t **ret, char *cn, long validity);

// generate an ID using supplied private key
// returns one of ABAC_SUCCESS or ABAC_GENERATE_* (see top)
int abac_id_generate_with_key(abac_id_t **ret, char *cn, long validity, char *keyfile);

// get the SHA1 keyid, pointer is valid for the lifetime of the object
char *abac_id_keyid(abac_id_t *id);

// get the CN of keyid, pointer is valid for the lifetime of the object
char *abac_id_cn(abac_id_t *id);

// get the name of the issuer
// caller must free the returned string
char *abac_id_issuer(abac_id_t *id);

// get the DN of the subject
// caller must free the returned string
char *abac_id_subject(abac_id_t *id);

// check if the cert is still valid
int abac_id_still_valid(abac_id_t *id);

// check if the principal cert's keyid is specified
int abac_id_has_keyid(abac_id_t *id, char *);

// check if the cert is has a private key
int abac_id_has_privkey(abac_id_t *id);

// get the validity period of the cert
int abac_id_validity(abac_id_t *id, struct tm *not_before, struct tm *not_after);

// default filename for the cert: ${CN}_ID.pem
// caller must free the returned string
char *abac_id_cert_filename(abac_id_t *id);

// write the cert fo an open file pointer
int abac_id_write_cert(abac_id_t *id, FILE *out);

// default filename for the private key: ${CN}_key.pem
// caller must free the return value
char *abac_id_privkey_filename(abac_id_t *id);

// write the private key to a file
// it is recommended that you open this file mode 0600
// returns false if there's no private key loaded
int abac_id_write_privkey(abac_id_t *id, FILE *out);

// get a chunk representing the cert
// you must free the ptr of the chunk when done
abac_chunk_t abac_id_cert_chunk(abac_id_t *id);

// get a chunk representing the private key of the id
abac_chunk_t abac_id_privkey_chunk(abac_id_t *id);

// dup an ID (increases its refcount)
abac_id_t *abac_id_dup(abac_id_t *id);

// destroy the id
// decreases refcount and destroys when it hits 0
void abac_id_free(abac_id_t *id);

/*
 * Operations on Attribute
 */
//
// Here's the skinny:
//  Attribute cert objects don't contain an actual cert until they're baked.
//  First you construct the object using abac_attribute_create, then you add
//  subjects to it using abac_attribute_{principal,role,linking_role}.
//  Finally you bake it. Once you've done that, you can keep it as XML chunk
//  or write it to a file.
//

// create an attribute cert
// validity is in days
// returns one of CREDDY_SUCCESS or CREDDY_ATTRIBUTE_* (see top)
int abac_attribute_create(abac_attribute_t **attr, abac_id_t *issuer, char *role, long validity);

// add a head string to the cert
void abac_attribute_set_head(abac_attribute_t *attr, char *string);

// return the head string of the attribute
char *abac_attribute_get_head(abac_attribute_t *);

// add a principal subject to the cert
int abac_attribute_principal(abac_attribute_t *attr, char *keyid);

// add a role subject
int abac_attribute_role(abac_attribute_t *attr, char *keyid, char *role);

// add a linking role subject
int abac_attribute_linking_role(abac_attribute_t *attr, char *keyid, char *role, char *linked);

// create the attribute cert once all the subjects have been added
// can return 0 if there are no subjects or there's a problem building the cert
int abac_attribute_bake(abac_attribute_t *attr);
int abac_attribute_bake_context(abac_attribute_t *attr, abac_context_t *ctxt);

// returns true iff the cert's been baked
int abac_attribute_baked(abac_attribute_t *attr);

// write the cert to a file. returns 0 if the cert hasn't been baked
int abac_attribute_write(abac_attribute_t *attr, FILE *out);
int abac_attribute_write_file(abac_attribute_t *attr, const char *fname);

/*
 * Return the number of tail strings
 */
int abac_attribute_get_ntails(abac_attribute_t *a);

/*
 * Return the nth tail string or NULL if it is undefined
 */
char *abac_attribute_get_tail_n(abac_attribute_t *a, int n);

// get chunked cert
// returns 0 if the cert isn't baked
abac_chunk_t abac_attribute_cert_chunk(abac_attribute_t *);

// destroy the cert
void abac_attribute_free(abac_attribute_t *);

// load a list of attr cert from file (aborts on fail)
ABAC_LIST_T *abac_attribute_certs_from_file(ABAC_LIST_T *,char *);

// load a list of attr cert from chunk (aborts on fail)
ABAC_LIST_T *abac_attribute_certs_from_chunk(ABAC_LIST_T *,abac_chunk_t);

	// get the attribute role string
char *abac_attribute_role_string(abac_attribute_t *attr);

// get the issuer id of an attribute
abac_id_t *abac_attribute_issuer_id(abac_attribute_t *ptr);

// get the attribute output format
char *abac_attribute_get_output_format(abac_attribute_t *);

// set the attribute output format
// Valid formats GENIv1.0, GENIv1.1
void abac_attribute_set_output_format(abac_attribute_t *, char *);

// get the validity period of the attribute cert
int abac_attribute_validity(abac_attribute_t *attr, struct tm *not_before, struct tm *not_after);
abac_keyid_map_t *abac_attribute_get_keyid_map(abac_attribute_t *);

// return the principal from an attribute's role string
// callee must free the space
char *abac_attribute_get_principal(abac_attribute_t *attr);

// check if the attribute cert is still valid
int abac_attribute_still_valid(abac_attribute_t *attr);

/* abac name mappings.  These are used internally, mostly */
abac_keyid_mapping_t *abac_keyid_mapping_new(char *k, char *v);
void abac_keyid_mapping_free(abac_keyid_mapping_t *m);
abac_keyid_map_t *abac_keyid_map_new();
abac_keyid_map_t *abac_keyid_map_dup(abac_keyid_map_t *);
abac_keyid_map_t *abac_keyid_map_clone(abac_keyid_map_t *);
void abac_keyid_map_free(abac_keyid_map_t *m); 
char *abac_keyid_map_key_to_nickname(abac_keyid_map_t *m, char *key);
char *abac_keyid_map_nickname_to_key(abac_keyid_map_t *m, char *nick); 
int abac_keyid_map_remove_keyid(abac_keyid_map_t *m, char *key); 
int abac_keyid_map_add_nickname(abac_keyid_map_t *m, char *key, char *nick);
void abac_keyid_map_merge(abac_keyid_map_t *d, abac_keyid_map_t *s, 
	int overwrite);
char *abac_keyid_map_expand_key(abac_keyid_map_t *m, char *s); 
char *abac_keyid_map_expand_nickname(abac_keyid_map_t *m, char *s);
/* 
 * Return code for libabac
 */
#define ABAC_RC_SUCCESS                0
#define ABAC_RC_FAILURE                1

/*
 * Error codes for loading certificates.
 */
#define ABAC_CERT_SUCCESS           0   // certificate loaded, all is well
#define ABAC_CERT_INVALID           -1  // invalid format; also file not found
#define ABAC_CERT_BAD_SIG           -2  // invalid signature
#define ABAC_CERT_MISSING_ISSUER    -3  // missing ID cert that issued the attribute cert
#define ABAC_CERT_BAD_PRINCIPAL     -4  // Principal of attribute cert issuer has mismatch keyid
#define ABAC_CERT_INVALID_ISSUER    -5  // Issuer of attribute cert is invalid
#define ABAC_CERT_SIGNER_NOKEY      -6  // Signer of attribute cert is missing private key

/*
 * Error codes for IDs and Attributes
 */
#define ABAC_SUCCESS                          0
#define ABAC_FAILURE                          1 /* catch all */
#define ABAC_GENERATE_INVALID_CN             -1
#define ABAC_GENERATE_INVALID_VALIDITY       -2
#define ABAC_ATTRIBUTE_ISSUER_NOKEY          -3
#define ABAC_ATTRIBUTE_INVALID_ROLE          -4
#define ABAC_ATTRIBUTE_INVALID_VALIDITY      -5
#define ABAC_ATTRIBUTE_INVALID_ISSUER        -6



#endif /* __ABAC_H__ */
