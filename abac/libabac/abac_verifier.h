#ifndef __VERIFIER_H__
#define __VERIFIER_H__

#include "abac.h"
#include "uthash.h"
#include "abac_verifier.h"

void abac_verifier_init(void);
void abac_verifier_deinit(void);

int abac_verifier_load_id_file(abac_list_t*,char *filename, abac_keyid_map_t *);
int abac_verifier_load_id_chunk(abac_list_t *,abac_chunk_t chunk, abac_keyid_map_t *);
int abac_verifier_load_attribute_cert_file(abac_list_t *,char *filename, abac_list_t *clist, abac_keyid_map_t *km);
int abac_verifier_load_attribute_cert_chunk(abac_list_t *,abac_chunk_t chunk, abac_list_t  *clist, abac_keyid_map_t *km);

void abac_id_cert_insert_cert(abac_list_t *, abac_id_cert_t *id_cert);
void abac_id_cert_delete_cert(abac_list_t *, abac_id_cert_t *id_cert);
abac_id_cert_t *abac_id_cert_dup(abac_id_cert_t *id_cert);
int abac_id_cert_count(abac_id_cert_t *);
char *abac_id_cert_keyid(abac_id_cert_t *);
char *abac_id_cert_cn(abac_id_cert_t *);
void abac_id_cert_free(abac_id_cert_t *);
int abac_verifier_load_id_id(abac_list_t *, abac_id_t *, abac_keyid_map_t *);

#endif /* __VERIFIER_H__ */
