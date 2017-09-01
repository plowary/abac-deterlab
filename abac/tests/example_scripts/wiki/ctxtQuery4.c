/**
   ctxtQuery4.

   testing mnemonic part of libabac in c

   call:   ./ctxtQuery4_r  coyote_attr.xml

gcc -g -I/home/mei/Deter/abac0-master-new/libabac -c ctxtQuery4.c -o ctxtQuery4.o
gcc -g -o ctxtQuery4_r ctxtQuery4.o -L/home/mei/Deter/abac0-master-new/libabac/.libs -labac -lm -lpthread -Wl,-rpath
**/

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <assert.h>

#include <abac.h>

extern char *abac_id_keyid(abac_id_t *id);

int main(int argc, char **argv) {
    int i, success=0;
    abac_credential_t *cred=NULL;
    abac_credential_t **credentials=NULL;
             
    abac_context_t *ctx = abac_context_new();
    int rc;  
             
    rc=abac_context_load_attribute_file(ctx, argv[1]);
    if(rc!=0) {
        printf("can not open file %s\n", argv[1]);
        return 1;
    }        
             
    credentials=abac_context_credentials(ctx);
    for (i = 0; credentials[i] != NULL; ++i) {
           cred = credentials[i];
           printf("credential %s <- %s\n",
                    abac_role_string(abac_credential_head(cred)),
                    abac_role_string(abac_credential_tail(cred)));          
           printf("short credential %s <- %s\n",
                    abac_role_short_string(abac_credential_head(cred),ctx),
                    abac_role_short_string(abac_credential_tail(cred),ctx));
    }
    if(credentials)
        abac_context_credentials_free(credentials);                       
             
    abac_context_free(ctx);
    return 0;
}            


