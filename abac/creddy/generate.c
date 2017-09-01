
/* generate.c */

#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "libabac_common.h"
#include "creddy_common.h"

void generate_main(options_t *opts) {
    int ret, fd;
    abac_id_t *id;
    char *filename;
    FILE *out;

    // make sure we have at least a CN
    if (opts->cn == NULL)
        usage(opts);

    // if we have an outdir, chdir there
    if (opts->out) {
        ret = chdir(opts->out);
        if (ret < 0)
            err(1, "can't open output directory '%s'", opts->out);
    }

    if(opts->key) {
        ret = abac_id_generate_with_key(&id, opts->cn, opts->validity, opts->key);
        } else {
            printf("Generating key, this will take a while. Create entropy!\n");
            printf("    - move the mouse\n");
            printf("    - generate disk activity (run find)\n");
            ret = abac_id_generate(&id, opts->cn, opts->validity);
    }

    if (ret == ABAC_GENERATE_INVALID_CN) {
        printf("Invalid CN: must start with a letter and be alphanumeric\n");
        usage(opts);
    }
    if (ret == ABAC_GENERATE_INVALID_VALIDITY) {
        printf("Validity must be >= 1 day\n");
        usage(opts);
    }
    // in both above cases: usage(opts) exits

    //
    // success!
    //

    // write the cert
    filename = abac_id_cert_filename(id);
    out = fopen(filename, "w");
    if (out == NULL)
        err(1, "Can't open cert file %s", filename);
    abac_id_write_cert(id, out);
    fclose(out);
    free(filename);

    // write the key if not supplied
    if(!opts->key) {
        filename = abac_id_privkey_filename(id);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600); // mode 600
        if (fd < 0)
            err(1, "Can't open private key file %s", filename);
        out = fdopen(fd, "w");
        abac_id_write_privkey(id, out);
        fclose(out);
    }

    abac_id_free(id);
}
