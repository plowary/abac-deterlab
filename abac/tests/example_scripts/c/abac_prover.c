/**
   abac_prover.c

   To demonstrate how to use ABAC's api in C to make a query

   call:   abac_prover "keystorestring" "rolestring" "principalstring"

   pre-condition: run make attr_abac  generate IceCream_ID.pem and IceCream_private.pem with

   This program will make a prover call using 
           rolestring <- principalstring

**/

#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <abac.h>

int main(int argc, char **argv) {
    int i, success=0;
    abac_credential_t *cred=NULL;
    abac_credential_t **credentials=NULL;

    abac_context_t *ctx = abac_context_new();
    abac_context_load_directory(ctx, argv[1]);

    char *query=strdup(argv[2]);
    char *with=strdup(argv[3]);

    printf("query %s \n", query);
    printf("with %s\n", with);

int k=10; /* use to do repetitions */
while(k) {
    credentials = abac_context_query(ctx,
                            query, with,
                            &success);
    if (success)
        puts("prover success!!");
        else puts("prover failed!!");

    if (credentials != NULL && success) {
        puts("credentials needed :");
        for (i = 0; credentials[i] != NULL; ++i) {
           cred = credentials[i];
           printf("credential %s <- %s\n",
                    abac_role_string(abac_credential_head(cred)),
                    abac_role_string(abac_credential_tail(cred)));
        }
    }
    if(credentials)
        abac_context_credentials_free(credentials);
    k=k-1;
}
    free(query);
    free(with);

{ /* dump credentials from context */
    printf("\n\n");
    credentials = abac_context_credentials(ctx);
    printf("Dump context credentials, original ctx \n");
    if (credentials != NULL) {
        puts("context credentials :");
        for (i = 0; credentials[i] != NULL; ++i) {
           cred = credentials[i];
           printf("credential %s <- %s\n",
                    abac_role_string(abac_credential_head(cred)),
                    abac_role_string(abac_credential_tail(cred)));
        }
    }
    if(credentials)
        abac_context_credentials_free(credentials);
}

    abac_context_t *ctx2 = abac_context_dup(ctx);
{ /* dump credentials from context */
    printf("\n\n");
    credentials = abac_context_credentials(ctx);
    printf("Dump context credentials, original ctx2 \n");
    if (credentials != NULL) {
        puts("context credentials :");
        for (i = 0; credentials[i] != NULL; ++i) {
           cred = credentials[i];
           printf("credential %s <- %s\n",
                    abac_role_string(abac_credential_head(cred)),
                    abac_role_string(abac_credential_tail(cred)));
        }
    }
    if(credentials)
        abac_context_credentials_free(credentials);
}

    abac_context_free(ctx);
    abac_context_free(ctx2);

    return 0;
}
