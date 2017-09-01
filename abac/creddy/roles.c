
/* roles.c */

#include <err.h>

#include "libabac_common.h"
#include "creddy_common.h"

void roles_main(options_t *opts) {
    if (opts->cert == NULL)
        usage(opts);

    abac_list_t *attr_list = abac_attribute_certs_from_file(NULL,opts->cert);
    if (abac_list_size(attr_list) == 0)
        errx(1, "Couldn't get cert from %s", opts->cert);

    abac_attribute_t *cert=NULL;
    abac_list_foreach(attr_list, cert,
            char *role_string=abac_attribute_role_string(cert);
            if (role_string != NULL) {
                puts(role_string);
                free(role_string);
            } else errx(1, "Couldn't get attributes from %s", opts->cert);
            abac_attribute_free(cert);
    );
    abac_list_free(attr_list);
}
