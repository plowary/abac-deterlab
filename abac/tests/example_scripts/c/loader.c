/**
CAN NOT RUN

   loader.c

   To demonstrate how to use ABAC's api in C to load credentials

   some not implemented yet 

   call:   abac_load 

**/

#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <abac.h>

int main(int argc, char **argv) {
    int i, success=0;
    abac_credential_t *cred=NULL;
    abac_credential_t **credentials=NULL;

    abac_context_t *ctx = abac_context_new();
    int rc;

fprintf(stderr, "\n         --- load from directory\n");
    if(argc==2)
        abac_context_load_directory(ctx, argv[1]); 
        else
            abac_context_load_directory(ctx, "."); 

fprintf(stderr, "\n         --- load from chunk\n");
    abac_id_t *tid;
    abac_id_generate(&tid,"Tim", 0);
    abac_chunk_t chunk=abac_id_cert_chunk(tid);
    tid=abac_id_from_chunk(chunk);
XXX  not implemented yet.. 
    rc=abac_context_load_id(ctx,tid); 

fprintf(stderr, "\n         --- load from id_gen\n");
    abac_id_t *id;
    abac_id_generate(&id,"Mary", 0);
    abac_id_write_cert_fname(id,"Mary_ID.pem");
    abac_id_write_privkey_fname(id,"Mary_private.pem");
fprintf(stderr, "\n         --- load from explicit call\n");
/*    int rc=abac_context_load_id_id_key_files(ctx,"Mary_ID.pem","Mary_private.pem"); */ 
    rc=abac_context_load_id(ctx,id); 

   
fprintf(stderr, "\n         --- load with idkey file\n");
    abac_id_t *id2;
    abac_id_generate(&id2,"Tom", 0);
    abac_id_write_cert_fname(id2,"Tom_IDKEY.pem");
    abac_id_write_privkey_fname(id2,"Tom_IDKEY.pem");
    rc=abac_context_load_id_file(ctx,"Tom_IDKEY.pem"); 

{
    printf("\n\n");
    credentials = abac_context_credentials(ctx);
    if (credentials != NULL) {
        puts("context credentials :");
        for (i = 0; credentials[i] != NULL; ++i) {
           cred = credentials[i];
           abac_print_typed_cred_info(cred,NULL);
        }
    }
    if(credentials)
        abac_free_credentials(credentials);
}
{
    abac_id_credential_t *id_cred=NULL;
    abac_id_credential_t **id_credentials=NULL;
    printf("\n\n");
    id_credentials = abac_context_principals(ctx);
    if (id_credentials != NULL) {
        puts("principal credentials :");
        for (i = 0; id_credentials[i] != NULL; ++i) {
           id_cred = id_credentials[i];
           abac_print_prin_info(id_cred,NULL);
        }
    }
    if(id_credentials)
        abac_free_principals(id_credentials);
}

    show_yap_db("yap db");

fprintf(stderr,"\n          --- id free from explicit call\n");
    abac_id_free(id);
    abac_id_free(id2);

fprintf(stderr,"\n          --- explicitly free the context \n");
    abac_context_free(ctx);

fprintf(stderr,"\n          --- that is it \n");
    return 0;
}
