
/* abac_attribute.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#include "libabac_common.h"
#include "abac_list.h"
#include "abac_util.h"
#include "abac_xml.h"

#define ROLE_SEPARATOR " <- "
#define INTERSECTION_SEP " & "
#define SHA1_LENGTH 40

#define DEFAULT_OUTPUT_FORMAT "GENIv1.1"

// a GENI XML attribute chunk might contain multiple 
// attribute rules. It will be translate into multiple
// abac_attribute structures but with cert ptr pointing
// to the same xml chunk
// issuer can be missing but then it won't be bakable
// unless it is baked just for creddy's roles call
struct _abac_attribute_t {
    abac_id_t *issuer_id; 
    char *role;
    long validity;
    int ntails;

    char *head_string;
    char **tail_strings;
    char *output_format;
    abac_keyid_map_t *keymap;

    abac_chunk_t cert; // the XML chunk
};

char *abac_attribute_role_string(abac_attribute_t *attr);
extern abac_id_t *abac_verifier_lookup_id(abac_list_t*, char *keyid);
static char *_validate_principal(char *keyid);

/************************************************************/
abac_chunk_t abac_attribute_cert(abac_attribute_t *ptr)
{
    assert(ptr);
    return ptr->cert;
}

abac_id_t *abac_attribute_issuer_id(abac_attribute_t *ptr)
{
    assert(ptr);
    return ptr->issuer_id;
}

/* Get the format for this attribute to be output in.  This is NULL if the
 * attribute has been read from a file. */
char *abac_attribute_get_output_format(abac_attribute_t *a) {
    return a->output_format;
}

/* Set the format for this attribute to be output in.  Valid formats are:
 * GENIv1.0
 * GENIv1.1
 */
void abac_attribute_set_output_format(abac_attribute_t *a, char *fmt) {
    if (a->output_format) 
	free(a->output_format);
    a->output_format = abac_xstrdup(fmt);
}


// validity is measured in seconds (as of 0.2.0)
// Acme.customer
int abac_attribute_create(abac_attribute_t **ret, abac_id_t *issuer_id, char *role, long validity) {
    libabac_init();
    if (!abac_id_has_privkey(issuer_id))
        return ABAC_ATTRIBUTE_ISSUER_NOKEY;
    if (!abac_clean_name(role))
        return ABAC_ATTRIBUTE_INVALID_ROLE;
    if (validity < 0)
        return ABAC_ATTRIBUTE_INVALID_VALIDITY;
    if (!abac_id_still_valid(issuer_id))
        return ABAC_ATTRIBUTE_INVALID_ISSUER;

    if(validity == 0) validity = (long)(60*60*24*(365));

    abac_attribute_t *attr = abac_xmalloc(sizeof(abac_attribute_t));
    if(issuer_id) attr->issuer_id = abac_id_dup(issuer_id);
        else attr->issuer_id = NULL;
    attr->role = abac_xstrdup(role);
    attr->validity = validity;

    attr->head_string = NULL;
    if ( asprintf(&attr->head_string,"%s.%s",abac_id_keyid(issuer_id),role) < 0)
	return -1;
    attr->ntails = 0;
    attr->tail_strings = NULL;
    attr->keymap = NULL;

    attr->output_format = abac_xstrdup(DEFAULT_OUTPUT_FORMAT);

    // NULL until baked
    attr->cert.ptr = NULL;
    attr->cert.len = 0;

    *ret = attr;
    return ABAC_SUCCESS;
}

/**
 * Get the validity period.(xml module returns the diff from expire time - now()
 */
int abac_attribute_validity(abac_attribute_t *attr,struct tm *not_before,struct tm *not_after) {
    assert(attr);
    memset(not_before, 0, sizeof(struct tm));
    memset(not_after, 0, sizeof(struct tm));

    time_t now;
    time(&now);
    gmtime_r(&now, not_before);
    char *xml=(char *)attr->cert.ptr;
    long validity=get_validity_from_xml(xml);

    time_t etime = now + validity;
    gmtime_r(&etime, not_after);

    if(validity == 0)
        return ABAC_FAILURE;
    return ABAC_SUCCESS;
}

int abac_attribute_still_valid(abac_attribute_t *attr)
{
    assert(attr);
    assert(attr->cert.ptr);
    long v=get_validity_from_xml((char *)attr->cert.ptr);
    if (v > 0.0)
        return 1;
    else return 0;
}

/* string is a malloc copy */
int abac_attribute_add_tail(abac_attribute_t *attr, char *string) {
    assert(attr);

    char **old_tail = attr->tail_strings;
    int newsize = (attr->ntails+1)*sizeof(char *);

    if ( !(attr->tail_strings = realloc(attr->tail_strings, newsize))) {
	attr->tail_strings = old_tail;
	return 0;
    }
    attr->tail_strings[attr->ntails++] = string;
    return 1;
}


void abac_attribute_set_head(abac_attribute_t *attr, char *string)
{
    assert(attr);
    attr->head_string=string;
}

char *abac_attribute_get_head(abac_attribute_t *attr)
{
    assert(attr);
    return attr->head_string;
}

/*
 * Return the number of tail strings
 */
int abac_attribute_get_ntails(abac_attribute_t *attr) {
    assert(attr);
    return attr->ntails;
}

/*
 * Return the nth tail string or NULL if it is undefined
 */

char *abac_attribute_get_tail_n(abac_attribute_t *attr, int n) {
    assert(attr);
    if ( n < 0 || n > attr->ntails) return NULL;
    return attr->tail_strings[n];
}


/* A.b->C, return copy of a A */
char *abac_attribute_get_principal(abac_attribute_t *attr)
{
    /* already a copy */
    char *tmp=abac_attribute_role_string(attr);
    char *head_tail[2];
    int ret = 2;
    abac_split(tmp, "<-", head_tail, &ret);
    if (ret != 2) goto err;
    abac_split(head_tail[0], ".", head_tail, &ret);
    if (ret != 2) goto err;
    char *prin=strdup(head_tail[0]);
    free(tmp);
    return prin;

err:     
     free(tmp);
     return NULL;
}

int abac_attribute_principal(abac_attribute_t *attr, char *keyid) {
    char *copy = _validate_principal(keyid);
    if (copy == NULL)
        return 0;

    return abac_attribute_add_tail(attr,copy);
}

int abac_attribute_role(abac_attribute_t *attr, char *keyid, char *role) {
    if (!abac_clean_name(role))
        return 0;

    char *copy = _validate_principal(keyid);
    char *newcopy=NULL;
    if (copy == NULL)
        return 0;

    int err = asprintf(&newcopy,"%s.%s", copy,role);
    free(copy);
    if (err < 0 ) return 0;
    return abac_attribute_add_tail(attr, newcopy);
}

int abac_attribute_linking_role(abac_attribute_t *attr, char *keyid, char *role, char *linked) {
    if (!abac_clean_name(role) || !abac_clean_name(linked))
        return 0;

    char *copy = _validate_principal(keyid);
    if (copy == NULL)
        return 0;

    char *newcopy=NULL;
    int err = asprintf(&newcopy,"%s.%s.%s", copy,role,linked);
    free(copy);
    if ( err < 0 ) return 0;
    return abac_attribute_add_tail(attr, newcopy);
}



// 0 for fail to bake, 1 is baked okay
int abac_attribute_bake_context(abac_attribute_t *attr, abac_context_t *ctxt) {
    assert(attr);
    assert(attr->head_string);
    assert(attr->tail_strings);
    abac_keyid_map_t *km = NULL;

    abac_chunk_t id_chunk = { NULL, 0 };
    int ret=abac_id_PEM(attr->issuer_id, &id_chunk);
    if(ret != ABAC_CERT_SUCCESS)
        return 0; 

    if ( ctxt && (km = abac_context_get_keyid_map(ctxt))) {
	if (attr->keymap) abac_keyid_map_free(attr->keymap);
	attr->keymap = abac_keyid_map_dup(km);
    }

    /* Make an new GENI abac credential with the rt0 rule that expires secs
     * from now.  cert is the PEM encoded X.509 of the issuer's certificate as
     * a string.  certlen is the length of cert.  Returns the XML. Caller is
     * responsible for freeing it. */
    char *attr_cert=make_credential(attr, attr->validity, 
	    (char *)id_chunk.ptr, id_chunk.len);

    /*free id_chunk */
    abac_chunk_free(&id_chunk);

    if (attr_cert == NULL)
        return 0;

    attr->cert.ptr = (unsigned char *) attr_cert;
    attr->cert.len = strlen(attr_cert);

    return 1;
}
// 0 for fail to bake, 1 is baked okay
int abac_attribute_bake(abac_attribute_t *attr) {
    return abac_attribute_bake_context(attr, NULL);
}

/* 
 * caller is responsible to free up the chunk after use
 */
abac_chunk_t abac_attribute_cert_chunk(abac_attribute_t *attr) {
    abac_chunk_t chunk= {NULL,0};

    if (abac_chunk_null(&attr->cert))
        return chunk;

    /* return the xml chunk */
    chunk.ptr=(unsigned char *) abac_xstrdup((char *) attr->cert.ptr);
    chunk.len = attr->cert.len;
    return chunk;
}

int abac_attribute_baked(abac_attribute_t *attr) {
    return (attr->cert.ptr != NULL);
}


static abac_attribute_t *_load_attr(abac_list_t *id_certs,char *rstring, char *xml, abac_keyid_map_t *km)
{
    /* make a copy of rle_string */
    char *role_string=abac_xstrdup(rstring);

    char *head_tail[2];
    char *role_rest[2];
    int ret = 2;
    abac_split(role_string, "<-", head_tail, &ret);
    if (ret != 2) return NULL; 

    char *keyid=get_keyid_from_xml(xml);
    abac_id_t *issuer_id=abac_verifier_lookup_id(id_certs,keyid);

    long validity=get_validity_from_xml(xml);
    
    abac_attribute_t *attr = abac_xmalloc(sizeof(abac_attribute_t));
    if(issuer_id)
        attr->issuer_id = abac_id_dup(issuer_id);
    else attr->issuer_id=NULL;
    attr->validity = validity;
    attr->ntails = 0;
    attr->tail_strings = NULL;

    /* If there is a keymap, make a reference to it. */
    if ( km ) attr->keymap = abac_keyid_map_dup(km);
    else attr->keymap = NULL;


    attr->head_string = abac_xstrdup(head_tail[0]);
    do {
	ret = 2;
	abac_split(head_tail[1], " & ", role_rest, &ret);
	abac_attribute_add_tail(attr, abac_xstrdup(role_rest[0]));
	head_tail[1] =role_rest[1];
    } while (ret == 2);

    char *tmp=strstr(attr->head_string,".");

    if (!tmp) return NULL;
    attr->role =abac_xstrdup(tmp+1);

    attr->cert.ptr = (unsigned char *) abac_xstrdup(xml);
    attr->cert.len = strlen(xml);

    attr->output_format = NULL;

    free(keyid);
    free(role_string);
    return attr;
}

abac_list_t *abac_attribute_certs_from_file(abac_list_t *id_certs,char *filename)
{
    libabac_init();
    abac_list_t *alist=abac_list_new();
    char *xml=NULL;
    char *rt0=NULL;
    abac_keyid_map_t *km = abac_keyid_map_new();

    char **rt0s=read_credential((void *)id_certs,filename, &xml, km);
    if(rt0s == NULL) { 
        abac_keyid_map_free(km);
        return alist;
    }
    if(xml == NULL || strlen(xml)==0) { 
        abac_keyid_map_free(km);
        return alist;
    }

    abac_attribute_t *attr;

    int i=0;
    do {
        rt0 = rt0s[i]; 
        if(rt0 == NULL) break;
        attr=_load_attr(id_certs,rt0, xml, km);
        if(attr)
            abac_list_add(alist, attr);
        free(rt0);
        i++;
    } while (rt0s[i] !=NULL);
    abac_keyid_map_free(km);

    free(rt0s);
    free(xml);

    return alist;
}

abac_list_t *abac_attribute_certs_from_chunk(abac_list_t *id_certs,abac_chunk_t chunk) {
    libabac_init();

    abac_list_t *alist=abac_list_new();
    char *xml=(char *)chunk.ptr;
    abac_keyid_map_t *km = abac_keyid_map_new();

    if(chunk.len==0) return alist;

    char **rt0s=get_rt0_from_xml((void *) id_certs, xml, km);
    char *rt0=NULL;
    if(rt0s==NULL) {
        abac_keyid_map_free(km);
        return alist;
    }

    abac_attribute_t *attr;
    int i=0;
    do {
        rt0 = rt0s[i]; 
        if(rt0 == NULL) break;
        attr=_load_attr(id_certs,rt0, xml, km);
        if(attr)
            abac_list_add(alist, attr);
        free(rt0);
        i++;
    } while (rt0s[i] !=NULL);
    abac_keyid_map_free(km);

    free(rt0s);
    return alist;
}

// returns ABAC_FAILURE if the cert hasn't been baked
int abac_attribute_write(abac_attribute_t *attr, FILE *out) {
    assert(attr != NULL);

    if (abac_chunk_null(&attr->cert))
        return ABAC_FAILURE;

    // write to file
    if(fwrite(attr->cert.ptr, attr->cert.len, 1, out) != 1 )
        return ABAC_FAILURE;

    return ABAC_SUCCESS;
}

// returns ABAC_FAILURE if the cert hasn't been baked
int abac_attribute_write_file(abac_attribute_t *attr, const char *fname) {
    if (abac_chunk_null(&attr->cert))
        return ABAC_FAILURE;

    FILE *fp=fopen(fname,"w+");
    if(fp) {
         // write to file
         if(fwrite(attr->cert.ptr, attr->cert.len, 1, fp) != 1)
             return ABAC_FAILURE;
    } else return ABAC_FAILURE;
    fclose(fp);

    return ABAC_SUCCESS;
}

/* return a copy of the local name mappings, if any.  The returned value is not
 * reference counted, so callers will need to call abac_keyid_map_dup on it if
 * they need to keep a copy of the pointer.
 */
abac_keyid_map_t *abac_attribute_get_keyid_map(abac_attribute_t *attr) {
    return attr->keymap;
}


void abac_attribute_free(abac_attribute_t *attr) {

    int i = 0;

    if (attr == NULL)
        return;

    if(attr->issuer_id) abac_id_free(attr->issuer_id);

    free(attr->role);
    free(attr->head_string);
    for (i=0; i < attr->ntails; i++) 
	free(attr->tail_strings[i]);
    free(attr->tail_strings);
    if ( attr->output_format ) 
	free(attr->output_format);

    if ( attr->keymap ) abac_keyid_map_free(attr->keymap);

    abac_chunk_free(&attr->cert);

    free(attr);
}

//
// Helper functions below
//

// validate a princpal's name
// makes sure it's a valid SHA1 identifier
// return values:
//  success: malloc'd copy with all hex digits lowercase
//  fail: NULL
static char *_validate_principal(char *keyid) {
    int i;
    char *copy = NULL;

    if (strlen(keyid) != SHA1_LENGTH)
        return NULL;

    copy = abac_xstrdup(keyid);
    for (i = 0; i < SHA1_LENGTH; ++i) {
        copy[i] = tolower(copy[i]);
        if (!isxdigit(copy[i]))
            goto error;
    }

    return copy;

error:
    free(copy);
    return NULL;
}

static int abac_attribute_role_string_size(abac_attribute_t *attr) {
    int sz = 3; /* Start with the end of string character and <-*/
    int i;	/* Scratch */

    if ( !attr) return sz;
    if ( attr->head_string) 
	sz += strlen(attr->head_string);
    for (i = 0; i < attr->ntails; i++) 
	if ( attr->tail_strings[i]) 
	    sz += strlen(attr->tail_strings[i]);
    /* " & " between each pair of tails */
    sz += 3 * (attr->ntails-1);
    return sz;
}

// combine up the attribute's rule string, explicit copy
char *abac_attribute_role_string(abac_attribute_t *attr) {
    assert(attr);

    int sz = abac_attribute_role_string_size(attr);
    char *role_string=abac_xmalloc(sz);
    int i;

    if ( !role_string) return NULL;

    sz -= snprintf(role_string, sz, "%s<-", attr->head_string);
    for ( i = 0 ; i < attr->ntails; i++ ) {
	if ( i > 0 ) {
	    strncat(role_string, " & ", 3);
	    sz -= 3;
	}
	strncat(role_string,attr->tail_strings[i], sz); 

	sz -= strlen(attr->tail_strings[i]);
	if (sz < 0 ) return NULL;
    }
    return role_string;
}
