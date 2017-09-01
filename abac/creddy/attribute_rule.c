
/* attribute_rule.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <err.h>
#include <termios.h>

#include "creddy_common.h"
#include "libabac_common.h"
#include "abac_util.h"

void add_tail(abac_attribute_t *a, char *t) {
    char *roles[256];	/* The roles in t, separated by ' & ' */
    int nroles = 256;	/* Number of slots in roles and then number found by
			   abac_split */
    int i;		/* Scratch */

    abac_split(t, " & ", roles, &nroles);

    for ( i = 0; i < nroles; i++ ) {
	char *terms[3];	/* The terms in roles[i] */
	int nterms = 3;	/* Number of slots and then number used  in terms */

	abac_split(roles[i], ".", terms, &nterms);
	switch (nterms) {
	    default:
		err(1, "Cannot parse term!!?");
		break;
	    case 1:
		abac_attribute_principal(a, terms[0]);
		break;
	    case 2:
		abac_attribute_role(a, terms[0], terms[1]);
		break;
	    case 3:
		abac_attribute_linking_role(a, terms[0], terms[1], terms[2]);
		break;
	}
    }
}



void attribute_rule_main(options_t *opts) {
    int ret;

    if (
        opts->issuer == NULL ||
        opts->key == NULL ||
        opts->attrrule == NULL ||
        opts->out == NULL
    )
        usage(opts);

    // issuer
    abac_id_t *issuer_id = abac_id_from_file(opts->issuer);
    if (issuer_id == NULL)
        errx(1, "Can't load cert from %s", opts->issuer);

    // private key
    ret = abac_id_privkey_from_file(issuer_id, opts->key);
    if (ret != ABAC_SUCCESS)
        errx(1, "Can't load private key from %s", opts->key);


    /* chop out the role, head_string, tail_string */
    char *head_tail[2];
    abac_split(opts->attrrule, "<-", head_tail, &ret);
    if (ret != 2) errx(1, "Invalid access rule");

    char *head_role[2];
    abac_split(head_tail[0], ".", head_role, &ret);
    if (ret != 2) errx(1, "Invalid access rule");
    char *keyid=abac_xstrdup(head_role[0]);
    char *role =abac_xstrdup(head_role[1]);

    /* make sure keyid match up with issuer */
    char *issuer=abac_id_keyid(issuer_id);
    if(strcmp(keyid,issuer)!=0) {
        errx(1, "Mismatched issuer with the access rule");
    }

    abac_attribute_t *attr = NULL;
    ret = abac_attribute_create(&attr, issuer_id, role, opts->validity);
    if (ret == ABAC_ATTRIBUTE_ISSUER_NOKEY)
        abort(); // should never happen
    if (ret == ABAC_ATTRIBUTE_INVALID_ROLE)
        errx(1, "Invalid role name: %s", role);
    if (ret == ABAC_ATTRIBUTE_INVALID_VALIDITY)
        errx(1, "Invalid validity: must be >= 1 second");

    add_tail(attr, head_tail[1]);

    ret = abac_attribute_bake(attr);
    if (!ret)
        errx(1, "Couldn't bake attribute cert");

    FILE *out = fopen(opts->out, "w");
    if (out == NULL)
        err(1, "Couldn't open attr cert file %s for writing", opts->out);

    abac_attribute_write(attr, out);

    fclose(out);

    abac_attribute_free(attr);
}
