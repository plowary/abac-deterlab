/**
CAN NOT RUN
   tchunk.c
   chunking test, no ready yet

**/

#include <err.h>
#include <stdio.h>
#include <assert.h>

#include <abac.h>

int main(int argc, char **argv) {
    int rc;

    abac_context_t *ctx = abac_context_new();

    if(argc != 4) return 1;

    /* build up structure */
    abac_id_t *id =NULL;
    id = abac_id_from_file(argv[2]);
/*
    int rc=abac_id_privkey_from_file(id,argv[3]);
*/

    int w=atoi(argv[1]);
    if(w==0) {
        printf("USING chunk...\n");
        abac_id_t *nid=abac_id_from_chunk(abac_id_cert_chunk(id));
        rc=abac_context_load_id_chunk(ctx, abac_id_cert_chunk(nid));
    } else {
        printf("USING NO chunk...\n");
/* no implemented 
        rc=abac_context_load_id_id(ctx, id);  
*/
    }
    abac_context_free(ctx);
    return 0;
}
