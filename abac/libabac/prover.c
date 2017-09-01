#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <abac.h>
#include "abac_list.h"
#include "options.h"

static void _dump_context(FILE *fp, abac_context_t *ctx)
{
    int i;
    abac_credential_t **credentials = abac_context_credentials(ctx);
    abac_credential_t *cred;
    if (credentials != NULL)
        for (i = 0; credentials[i] != NULL; ++i) {
            cred = credentials[i];
            fprintf(fp,"%s <- %s\n",
                abac_role_string(abac_credential_head(cred)),
                abac_role_string(abac_credential_tail(cred)));
        }
    abac_context_credentials_free(credentials);

    abac_id_cert_t **ilist=abac_context_principals(ctx);
    abac_id_cert_t *cert;
    if (ilist != NULL)
        for (i = 0; ilist[i] != NULL; ++i) {
               cert = ilist[i];
               fprintf(fp,"id[%d] %s (%s)\n",i, abac_id_cert_keyid(cert), abac_id_cert_cn(cert));
        }
    abac_context_id_credentials_free(ilist);
}

int main(int argc, char **argv) {
    int i, success;
    abac_credential_t *cred;

    options_t opts = { 0, };
    get_options(argc, argv, &opts);

    abac_context_t *ctx = abac_context_new();
    abac_context_load_directory(ctx, opts.keystore);

    if(opts.rulefile) {
        FILE *fp=fopen(opts.rulefile,"w+");
        if(fp) { 
            _dump_context(fp,ctx);       
            fclose(fp);
        }
        if(opts.role == NULL) { /* just a pure dump call */
            free_options(&opts);
            abac_context_free(ctx);
            return 0;
        }
    }

    abac_credential_t **credentials = abac_context_query(ctx,
        opts.role, opts.principal,
        &success
    );


    if (success)
        puts("success");
    else
        puts("fail, here's a partial proof");

    if (credentials != NULL)
        for (i = 0; credentials[i] != NULL; ++i) {
            cred = credentials[i];
            printf("credential %s <- %s\n",
                    abac_role_string(abac_credential_head(cred)),
                    abac_role_string(abac_credential_tail(cred))
                  );
        }

    abac_context_credentials_free(credentials);
    abac_context_free(ctx);
    free_options(&opts);

    if(success) {
        fprintf(stderr,"returning success- 0\n");
        return 0;
    } else {
        fprintf(stderr,"returning failure- 1\n");
        return 1;
    }
}
