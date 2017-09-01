/**
   attr4.c

   testing mnemonic part of libabac in c

   call:   ./attr4_r issuer.pem  (issuer.pem is from attr4_setup.py)

gcc -g -I/home/mei/Deter/abac0-master-new/libabac -c attr4.c -o attr4.o
gcc -g -o attr4_r attr4.o -L/home/mei/Deter/abac0-master-new/libabac/.libs -labac -lm -lpthread -Wl,-rpath
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

    rc=abac_context_load_id_file(ctx, argv[1]);
    if(rc!=0) {
        printf("can not open file %s\n", argv[1]);
        return 1;
    }

    /* build up structure */
    abac_id_t *id =NULL;
    id = abac_id_from_file(argv[1]);
    abac_context_set_nickname(ctx, abac_id_keyid(id), "Ted");

    abac_attribute_t *attr;
    rc=abac_attribute_create(&attr, id, "ABAC_Guy", 1800);
    abac_attribute_principal(attr, abac_id_keyid(id));
    rc=abac_attribute_bake_context(attr,ctx);

    printf(" attribute being made : %s\n",abac_attribute_role_string(attr));

    abac_attribute_write_file(attr,"ted_attr.xml");

    abac_context_free(ctx);
    return 0;
}
