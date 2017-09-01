
/* verify.c */

#include <err.h>
#include <string.h>

#include "libabac_common.h"
#include "creddy_common.h"

int debug=0;

extern int abac_list_size(abac_list_t *);

// verify can only valiate that the issuer and the attribute credential
// are still valid currently and the issuer's keyid is the same as that
// of the signing issuer id of the attribute credential
static void _validate(abac_attribute_t *subjec_cert, abac_id_t *cert);
static void _validate_id(abac_id_t *cert);

void verify_main(options_t *opts) {
    if (opts->cert == NULL)
        usage(opts);

    abac_id_t *issuer_id = abac_id_from_file(opts->cert);
    printf("creddy verify, issuer: %s\n", opts->cert);
    if(opts->attrcert)
        printf("               attribute cert: %s\n",opts->attrcert);

    if (issuer_id == NULL)
        errx(1, "Can't load issuer cert from %s", opts->cert);

    if (opts->attrcert != NULL) {
        abac_list_t *attr_list = abac_attribute_certs_from_file(NULL,opts->attrcert);
        abac_attribute_t *subject_attr=NULL;
        int sz=abac_list_size(attr_list);
        if(sz) {
            abac_list_foreach(attr_list, subject_attr,
                _validate(subject_attr, issuer_id);
                abac_attribute_free(subject_attr);
            );
            } else {
               printf("  fail to extract attribute cert but...\n");
               _validate_id(issuer_id);
        }
        abac_list_free(attr_list);
        } else { /* just check issuer_id */ 
            _validate_id(issuer_id);
    }
    abac_id_free(issuer_id);

}

static void _validate(abac_attribute_t *attr, abac_id_t *issuer)
{
    // checking for matching principal keyid
    char *prin=abac_attribute_get_principal(attr);
    char *keyid=abac_id_keyid(issuer);
    if(strcmp(prin,keyid) != 0)
        printf("  issuer and attribute cert have mismatched principals\n");
        else printf("  issuer and attribute cert have matching principals\n");
    free(prin);

    if(!abac_id_still_valid(issuer))
        printf("  issuer cert not valid now\n");
        else printf("  issuer cert still valid\n");

    if(!abac_attribute_still_valid(attr))
        printf("  attribute cert not valid now\n");
        else printf("  attribute cert still valid\n");
}

static void _validate_id(abac_id_t *issuer)
{
    if(!abac_id_still_valid(issuer))
        printf("  issuer cert not valid now\n");
        else printf("  issuer cert still valid\n");
}

