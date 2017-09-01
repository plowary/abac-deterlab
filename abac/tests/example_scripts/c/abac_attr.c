/**
   attr_abac.c

   To demonstrate how to use ABAC's api in C

   call:   attr_abac IceCream_ID.pem IceCream_private.pem IceCream_attr.der

   pre-condition: generate IceCream_ID.pem and IceCream_private.pem with
           creddy --generate --cn IceCream
                  generate Chocolate_ID.pem and Chocolate_private.pem with
           creddy --generate --cn IceCream

   This program will generate an attribute rule, write it out to an external
           file and also load it into the context (prolog db)
           [keyid:IceCream].delicious <- [Keyid:Chocolate]

   Then, a query is made against the context to see if it is populated correctly.

./abac_attr IceCream_ID.pem  IceCream_private.pem IceCream_attr.der Chocolate_ID.pem
**/

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <abac.h>

extern char *abac_id_keyid(abac_id_t *id);

void check_return(int rc, int ok, char *msg) {
    if ( rc != ok) {
	fprintf(stderr, "%s failed: %d expected %d\n",
		(msg) ? msg : "No message", rc, ok);
	exit(20);
    }
}

int main(int argc, char **argv) {
    int i, success=0;
    abac_credential_t *cred=NULL;
    abac_credential_t **credentials=NULL;

    abac_context_t *ctx = abac_context_new();

    if(argc != 5) return 1;

    /* build up structure */
    abac_id_t *id =NULL;
    id = abac_id_from_file(argv[1]);
    int rc=abac_id_privkey_from_file(id,argv[2]);

    abac_chunk_t a_chunk=abac_id_cert_chunk(id);
    rc=abac_context_load_id_chunk(ctx, a_chunk);
    check_return(rc, 0, "load_id_chunk");
    abac_chunk_free(&a_chunk);

    abac_id_t *chocolate_id = abac_id_from_file(argv[4]);
    rc=abac_context_load_id_id(ctx, chocolate_id);
    check_return(rc, 0, "load_id_id");

    abac_attribute_t *attr;
    rc=abac_attribute_create(&attr, id, "delicious", 0);
    check_return(rc, 0, "attribute_create");
    abac_attribute_principal(attr, abac_id_keyid(chocolate_id));
    rc=abac_attribute_bake(attr);
    check_return(rc, 1, "attribute_bake");

    char *string=abac_attribute_role_string(attr);
    printf(" attribute being made : %s\n",string);
    free(string);

    abac_attribute_write_file(attr,argv[3]);
    abac_chunk_t c_chunk=abac_attribute_cert_chunk(attr);
    rc = abac_context_load_attribute_chunk(ctx,c_chunk);
    check_return(rc, 0, "load_attribute_chunk");
    abac_chunk_free(&c_chunk);

    char *tmp=NULL;
    asprintf(&tmp,"%s.delicious",abac_id_keyid(id));

    /* make a query */
    credentials = abac_context_query(ctx,
        tmp, abac_id_keyid(chocolate_id),
        &success
    );


    fprintf(stderr,"query with %s\n",tmp);
    fprintf(stderr,"      for %s\n",abac_id_keyid(chocolate_id));
    int sz=abac_list_size(credentials);

    if (success)
        puts("attr success");
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

    free(tmp);
    abac_id_free(id);
    abac_attribute_free(attr);
    abac_context_free(ctx);

    return 0;
}
