#ifndef __LIBABAC_COMMON_H__
#define __LIBABAC_COMMON_H__

#include "abac.h"
#include "abac_list.h"

void libabac_init();

/* helper functions */

// generate a random serial (8byte)
unsigned char *abac_generate_serial();

// returns true if a name starts with a letter and 
//  is otherwise alphanumeric
int abac_clean_name(char *string);

// return a PEM blob of the ID cert
abac_chunk_t abac_id_in_PEM(abac_id_t *id);

// return a PEM blob of the ID/PKEY 
int abac_id_PEM(abac_id_t *id, abac_chunk_t *);

// return a blob of the Attribute cert
abac_chunk_t abac_attribute_cert(abac_attribute_t *ptr);

// used by creddy
char *abac_attribute_role_string(abac_attribute_t *attr);

// called by abac_verifier 
int init_xmlsec();
int deinit_xmlsec();

// called by abac_verifier
int init_openssl();
int deinit_openssl();


#endif /* __LIBABAC_COMMON_H__ */

