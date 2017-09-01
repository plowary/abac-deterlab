
/* attribute.c */

#define _GNU_SOURCE
#include <stdio.h>

#include <err.h>
#include <termios.h>

#include "libabac_common.h"
#include "creddy_common.h"

void attribute_main(options_t *opts) {
    int i, ret= 1;

    if (
        opts->issuer == NULL ||
        opts->key == NULL ||
        opts->role == NULL ||
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

    abac_attribute_t *attr = NULL;
    ret = abac_attribute_create(&attr, issuer_id, opts->role, opts->validity);
    if (ret == ABAC_ATTRIBUTE_ISSUER_NOKEY)
        abort(); // should never happen
    if (ret == ABAC_ATTRIBUTE_INVALID_ROLE)
        errx(1, "Invalid role name: %s", opts->role);
    if (ret == ABAC_ATTRIBUTE_INVALID_VALIDITY)
        errx(1, "Invalid validity: must be >= 1 second");

    for (i = 0; i < opts->num_subjects; ++i) {
        subject_t *cur = &opts->subjects[i];

        // if we have a cert we need to get its ID
        if (cur->cert) {
            abac_id_t *subject = abac_id_from_file(cur->cert);
            if (subject == NULL)
                errx(1, "Can't load subject cert from %s", cur->cert);
            cur->id = xstrdup(abac_id_keyid(subject));
            abac_id_free(subject);
        }

        // just a principal, add it
        if (!cur->role) {
	    abac_attribute_principal(attr, cur->id);
        }

        // either role or linking role
        else {
            char *role = cur->role;
            char *start[3];
            int name_parts = 0, j;

            start[name_parts++] = role;

            // split the role string up into name parts (turn . into \0)
            for (j = 0; role[j] != '\0'; ++j)
                if (role[j] == '.') {
                    if (name_parts == 3) {
                        printf("bad subject role name (too many dots)\n");
                        usage(opts);
                    }
                    start[name_parts++] = &role[j+1];
                    role[j] = 0;
                }

            // role
            if (name_parts == 1) {
		abac_attribute_role(attr, cur->id, start[0]);
            }
            // linking role
            else {
		abac_attribute_linking_role(attr, cur->id, start[0], start[1]);
            }
        }
    }

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
