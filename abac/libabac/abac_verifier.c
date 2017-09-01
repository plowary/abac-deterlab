
/* abac_verifier.c */
#include <assert.h>
#include <string.h>

#include "libabac_common.h"
#include "abac.h"
#include "abac_list.h"
#include "abac_util.h"

struct _abac_id_cert_t {
    char *keyid; // using cert's keyid
    abac_id_t *cert;
};

struct _abac_credential_t {
    abac_role_t *head;
    abac_role_t *tail;
    abac_id_t *issuer; /* Acme of Acme.customer <- Coyote */
    abac_attribute_t *cert;

    int refcount;
};

extern int abac_id_pass_privkey_from_id(abac_id_t *to_id, abac_id_t *from_id);
extern char *make_pem_from_naked_pem(char *naked_pem);

/***********************************************************************/
// convert a chunk to a lowercase binary string
// malloc's the string
/*** not used,
static char *_chunk_to_string(abac_chunk_t chunk) {
    int i;

    char *ret = abac_xmalloc(chunk.len * 2 + 1);

    for (i = 0; i < chunk.len; ++i)
        sprintf(ret + 2 * i, "%02x", chunk.ptr[i]);

    return ret;
}
***/

// verify that cert was issued by issuer
// cert and issuer can be the same, in which case the self-sig is validated
/*** not used
static int _verify_cert(abac_id_t *cert) {

    assert(cert); 
    if(!abac_id_still_valid(cert))
        return 0;
    return 1;
}
***/

/**
 * Init the verifier subsystem.
 */
void abac_verifier_init(void) {
    init_openssl();
    init_xmlsec();
}

/**
 * Uninitialize the system, free up any allocated memory.
 */
void abac_verifier_deinit(void) {
    deinit_xmlsec();
    deinit_openssl();
}

static abac_id_cert_t *_lookup_cert(abac_list_t *id_certs, char *keyid)
{
    abac_id_cert_t *id_cert=NULL;
    if(id_certs != NULL) {
        abac_list_foreach(id_certs, id_cert,
            if(strcmp(keyid,id_cert->keyid)==0)
               return id_cert;
        );
    }
    return NULL;
}

/**
 * Load an ID certificate.
 */
static int _load_id(abac_list_t *id_certs, abac_id_t **cert, 
	abac_keyid_map_t *km) {
    abac_id_cert_t *id_cert = NULL;
    char *keyid = NULL;
    char *nick = NULL;
    int ret;

    assert(*cert);

    // get the key ID
    keyid = abac_id_keyid(*cert);

    // if we already have this cert 'error' with success
    id_cert=_lookup_cert(id_certs, keyid);

    if (id_cert != NULL) {
        /* special case, if
           existing id does not have private key and
           incoming does, then need to bring that bit of
           information in */
           if(abac_id_has_privkey(*cert) && 
                       !abac_id_has_privkey(id_cert->cert)) {
               abac_id_pass_privkey_from_id(id_cert->cert, *cert);
           }
        /* free the new one and set the ptr to dup of old */
        abac_id_free(*cert);
        *cert=abac_id_dup(id_cert->cert);
        ret = ABAC_CERT_SUCCESS; 
        goto error;
    }

    ret = abac_id_still_valid(*cert);
    if (!ret) {
        ret = ABAC_CERT_INVALID;
        goto error;
    }

    // success, add the key to the map of certificates
    id_cert = abac_xmalloc(sizeof(abac_id_cert_t));
    id_cert->keyid = abac_xstrdup(keyid);
    id_cert->cert = *cert;
    abac_list_add(id_certs, id_cert); 
    /* Add the new id and issuer to the keyid <-> name map */
    if ( km && keyid && *cert ) {
	if ( (nick= abac_id_issuer(*cert)) ) {
	    /* If the issuer starts with /CN=, as many do, 
	     * trim the /CN= off */
	    if (!strncmp(nick, "/CN=", 4) && strlen(nick) > 4) 
		abac_keyid_map_add_nickname(km, keyid, nick+4);
	    else
		abac_keyid_map_add_nickname(km, keyid, nick);
	    free(nick);
	}
    }


    return ABAC_CERT_SUCCESS;

error:
    // No one owns cert, so delete it.
    if (*cert != NULL) abac_id_free(*cert);

    return ret;
}

abac_id_t *abac_verifier_lookup_id(abac_list_t *id_certs, char *keyid)
{
    abac_id_cert_t *id_cert=_lookup_cert(id_certs,keyid);
    if(id_cert == NULL) return NULL;
    return id_cert->cert;
}

/**
 * Load an ID cert from a file.
 */
int abac_verifier_load_id_file(abac_list_t *id_certs, char *filename,
	abac_keyid_map_t *km) {
    // load the cert
    abac_id_t *cert = abac_id_from_file(filename);

    if (cert == NULL)
        return ABAC_CERT_INVALID;

    return _load_id(id_certs,&cert, km);
}

/**
 * Load an ID cert from a chunk.
 */
int abac_verifier_load_id_chunk(abac_list_t *id_certs,abac_chunk_t chunk, 
	abac_keyid_map_t *km) {

    // load the cert
    abac_id_t *cert= abac_id_from_chunk(chunk);

    if (cert == NULL)
        return ABAC_CERT_INVALID;

    return _load_id(id_certs,&cert, km);
}

/**
 * Load an ID cert with an id
 */
int abac_verifier_load_id_id(abac_list_t *id_certs,abac_id_t *id, 
	abac_keyid_map_t *km) {

    if (id == NULL)
        return ABAC_CERT_INVALID;

    return _load_id(id_certs,&id, km);
}

/**
 * Load an ID cert from a char ptr of a X509 pem data
 * this is called from parse_privilege/parse_abac
 */
int abac_verifier_load_id_chars(abac_list_t *id_certs,char *naked_pem, 
	abac_keyid_map_t *km) {
    /* if id_certs is NULL, don't even try to load it */
    if(id_certs == NULL) return ABAC_CERT_SUCCESS;
    /* make a well formed pem from this */
    char *new_naked_pem=abac_xstrdup(naked_pem);
    char *pem=make_pem_from_naked_pem(new_naked_pem);
    int len=strlen(pem);
    free(new_naked_pem);

    abac_chunk_t chunk = { (unsigned char *) pem, len }; 
    int rc=abac_verifier_load_id_chunk(id_certs,chunk, km);
    abac_chunk_free(&chunk);
    return rc;
    
}
/**
 * Load an attribute cert.
 * Returns true only if the certificate is valid and is issued by the proper
 * authority.
 */
static int _load_attribute_cert(abac_list_t *id_certs,abac_attribute_t *cert, 
	abac_credential_t **cred_ret, abac_keyid_map_t *km) {
    abac_role_t *head_role = NULL;
    abac_role_t *tail_role = NULL;
    abac_id_cert_t *issuer=NULL;
    abac_keyid_map_t *local_names = NULL;
    int ret;

    char *attr_string=abac_attribute_role_string(cert);

    if(attr_string == NULL) {
       ret = ABAC_CERT_INVALID;
       goto error;
    }

    // split into head/tail parts
    char *head_tail[2];
    ret = 2;
    abac_split(attr_string, "<-", head_tail, &ret);
    if (ret != 2) {
        ret = ABAC_CERT_INVALID;
        goto error;
    }

    // must be a role
    head_role = abac_role_from_string(head_tail[0]);
    if (head_role == NULL) goto error;
    if (!abac_role_is_role(head_role)) {
        ret = ABAC_CERT_INVALID;
        goto error;
    }

    // make sure the tail's valid too
    tail_role = abac_role_from_string(head_tail[1]);
    if (tail_role == NULL) {
        ret = ABAC_CERT_INVALID;
        goto error;
    }

    char *principal = abac_role_principal(head_role);
    issuer=_lookup_cert(id_certs,principal);
    if (issuer == NULL) {
        ret = ABAC_CERT_MISSING_ISSUER;
        goto error;
    }

    // check if issuer is still valid
    if (!abac_id_still_valid(issuer->cert)) {
        ret = ABAC_CERT_INVALID_ISSUER;
        goto error;
    }

    // make sure principal match up with keyid
    if(!abac_id_has_keyid(issuer->cert,principal)) {
        ret = ABAC_CERT_BAD_PRINCIPAL;
        goto error;
    }

    if ( (local_names = abac_attribute_get_keyid_map(cert)) && km ) 
	abac_keyid_map_merge(km, local_names, 1);
    
    // at this point we know we have a good attribute cert
    abac_credential_t *cred = abac_xmalloc(sizeof(abac_credential_t));
    cred->head = head_role;
    cred->tail = tail_role;
    cred->cert = cert;

    /* acme's cert */
    cred->issuer = abac_id_dup(issuer->cert);
    cred->refcount = 1;
    *cred_ret = cred;

    free(attr_string);

    return ABAC_CERT_SUCCESS;

error:
    free(attr_string);
    if (head_role != NULL) abac_role_free(head_role);
    if (tail_role != NULL) abac_role_free(tail_role);

    return ret;
}

static int _load_attribute_certs(abac_list_t *id_certs,abac_list_t *attr_list, 
	abac_list_t *cred_list, abac_keyid_map_t *km) {

    int sz=abac_list_size(attr_list);
    abac_credential_t *cred_ret=NULL;
    abac_attribute_t *attr;
    if(sz) { 
        abac_list_foreach(attr_list, attr,
            /* attr is being used to build cred_ret, so, don't remove it */
            int ret=_load_attribute_cert(id_certs, attr, &cred_ret, km);
            if(ret==ABAC_CERT_SUCCESS) {
                abac_list_add(cred_list, cred_ret);
            }
        );
    }

/* just free the list ptr */
    abac_list_free(attr_list);
    return sz;
}

/**
 * Load an attribute cert from a file.
 */
int abac_verifier_load_attribute_cert_file(abac_list_t *id_certs,char *filename, abac_list_t *cred_list, abac_keyid_map_t *km) {

    // load the cert
    abac_list_t *attr_list = abac_attribute_certs_from_file(id_certs,filename);

    if (abac_list_size(attr_list) == 0) {
        abac_list_free(attr_list);
        return ABAC_CERT_INVALID;
    }

    int ret=_load_attribute_certs(id_certs,attr_list, cred_list, km);

    if(ret) return ABAC_CERT_SUCCESS;
        return ABAC_CERT_INVALID;
}

/**
 * Load an attribute cert from a chunk.
 */
int abac_verifier_load_attribute_cert_chunk(abac_list_t *id_certs,abac_chunk_t chunk, abac_list_t *cred_list, abac_keyid_map_t *km) {

    // load the cert
    abac_list_t *attr_list = abac_attribute_certs_from_chunk(id_certs,chunk);

    if (abac_list_size(attr_list) == 0)
        return ABAC_CERT_INVALID;

    int ret=_load_attribute_certs(id_certs,attr_list,cred_list, km);

    if(ret) return ABAC_CERT_SUCCESS;
        return ABAC_CERT_INVALID;
}

/**
 * Return the head role.
 */
abac_role_t *abac_credential_head(abac_credential_t *cred) {
    return cred->head;
}

/**
 * Return the tail role.
 */
abac_role_t *abac_credential_tail(abac_credential_t *cred) {
    return cred->tail;
}

/**
 * Return the xml chunk of the attribute cert.
 */
abac_chunk_t abac_credential_attribute_cert(abac_credential_t *cred) {
    assert(cred); assert(cred->cert);
    return abac_attribute_cert_chunk(cred->cert);
}

/**
 * Return the chunk of the issuer cert.
 */
abac_chunk_t abac_credential_issuer_cert(abac_credential_t *cred) {
    assert(cred); assert(cred->issuer);
    abac_chunk_t ret= abac_id_in_PEM(cred->issuer);
    return ret;
}

/**
 * Increase the ref count of a credential.
 */
abac_credential_t *abac_credential_dup(abac_credential_t *cred) {
    assert(cred != NULL);

    ++cred->refcount;
    return cred;
}

abac_id_cert_t *abac_id_cert_dup(abac_id_cert_t *id_cert) {
    assert(id_cert != NULL && id_cert->keyid!=NULL);

    abac_id_cert_t *new_cert = abac_xmalloc(sizeof(abac_id_cert_t));
    new_cert->keyid=abac_xstrdup(id_cert->keyid);
    new_cert->cert=abac_id_dup(id_cert->cert);
 
    return new_cert;
}


/**
 * Decrease the reference count of a credential, freeing it when it reaches 0.
 */
void abac_credential_free(abac_credential_t *cred) {
    if (cred == NULL)
        return;

    --cred->refcount;
    if (cred->refcount > 0)
        return;

    abac_role_free(cred->head);
    abac_role_free(cred->tail);
    abac_attribute_free(cred->cert);
    abac_id_free(cred->issuer);

    free(cred);
}

/**
 * remove an id cert, (not reference counted, so abac_id_certs are 
 * deep-copied)
 */
void abac_id_cert_free(abac_id_cert_t *id_cert) {
    if (id_cert==NULL)
        return;

    abac_id_free(id_cert->cert);
    if(id_cert->keyid) free(id_cert->keyid);
    free(id_cert);
}

char *abac_id_cert_keyid(abac_id_cert_t *id_cert)
{
    assert(id_cert);
    return id_cert->keyid;
}

char *abac_id_cert_cn(abac_id_cert_t *id_cert)
{
    assert(id_cert);
    return abac_id_cn(id_cert->cert);
}



