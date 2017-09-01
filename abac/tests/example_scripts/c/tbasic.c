/**
   tbasic.c

   bring up and taking down a context

**/

#include <err.h>
#include <stdio.h>
#include <assert.h>

#include <abac.h>

int main(int argc, char **argv) {
    int i, success=0;
    abac_credential_t *cred=NULL;
    abac_credential_t **credentials=NULL;

    printf("calling main ..\n");
    abac_context_t *ctxt = abac_context_new();
    abac_context_t *ctxt2 = abac_context_new();
    printf("done calling main ..\n");

    abac_context_free(ctxt2);

    return 0;
}
