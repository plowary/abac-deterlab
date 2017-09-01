
/* keyid.c */
#include <err.h>

#include "libabac_common.h"
#include "creddy_common.h"

void keyid_main(options_t *opts) {
    if (opts->cert == NULL)
        usage(opts);

    abac_id_t *id = abac_id_from_file(opts->cert);
    if (id == NULL)
        errx(1, "Couldn't load ID cert from %s", opts->cert);

    puts(abac_id_keyid(id));

    abac_id_free(id);
}
