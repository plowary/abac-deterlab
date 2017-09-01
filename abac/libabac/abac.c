/* abac.c */

#include <assert.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <dirent.h>

#include "abac.h"
#include "abac_list.h"
#include "abac_graph.h"
#include "abac_util.h"
#include "abac_verifier.h"

abac_id_cert_t **abac_context_principals(abac_context_t *ctx);
void abac_context_id_credentials_free(abac_id_cert_t **id_credentials);

struct _abac_context_t {
/* list of principal id credentials, abac_id_cert_t */
    abac_list_t *id_certs;
    abac_graph_t *graph;
    abac_keyid_map_t *keymap;
};

/**
 * Init the library.
 */
void libabac_init(void) {
    void libabac_deinit(void);
    static int has_been_init = 0;

    // called every time a context is created, so only do it once
    if (!has_been_init) {
        abac_verifier_init();
        atexit(libabac_deinit);
        has_been_init = 1;
    }
}

/**
 * Deinit the library.
 */
void libabac_deinit(void) {
    abac_verifier_deinit();
}

/**
 * Create a new abac context.
 */
abac_context_t *abac_context_new(void) {
    libabac_init();

    abac_context_t *ctx = abac_xmalloc(sizeof(abac_context_t));
    ctx->graph = abac_graph_new();
    ctx->id_certs=abac_list_new();
    ctx->keymap = abac_keyid_map_new();
    return ctx;
}

/**
 * Deep copy an abac context.
 */
abac_context_t *abac_context_dup(abac_context_t *ctx) {
    assert(ctx != NULL);
   
    abac_context_t *dup = abac_xmalloc(sizeof(abac_context_t));
    dup->graph = abac_graph_dup(ctx->graph);
    dup->id_certs=abac_list_new();

    abac_id_cert_t *id_cert;
    abac_list_foreach(ctx->id_certs, id_cert,
        abac_list_add(dup->id_certs, abac_id_cert_dup(id_cert));
    );

    dup->keymap = abac_keyid_map_clone(ctx->keymap);
    return dup;
}

/**
 * Free an abac context.
 */
void abac_context_free(abac_context_t *ctx) {
    assert(ctx != NULL);

    abac_graph_free(ctx->graph);

    abac_id_cert_t *id_cert;
    abac_list_foreach(ctx->id_certs, id_cert,
        abac_id_cert_free(id_cert);
    );
    abac_list_free(ctx->id_certs);
    abac_keyid_map_free(ctx->keymap);
    free(ctx);
}

/**
 * Load an ID cert from a file.
 */
int abac_context_load_id_file(abac_context_t *ctx, char *filename) {
    assert(ctx != NULL); assert(filename != NULL);
    return abac_verifier_load_id_file(ctx->id_certs,filename, ctx->keymap);
}

/**
 * Load an ID cert from a chunk.
 */
int abac_context_load_id_chunk(abac_context_t *ctx, abac_chunk_t cert_chunk) {
    assert(ctx != NULL);
    return abac_verifier_load_id_chunk(ctx->id_certs,cert_chunk, ctx->keymap);
}

/**
 * Load an ID cert from a id.
 */
int abac_context_load_id_id(abac_context_t *ctx, abac_id_t *id) {
    assert(ctx != NULL);
    return abac_verifier_load_id_id(ctx->id_certs,id, ctx->keymap);
}


/**
 * Load an attribute cert from a file.
 */
int abac_context_load_attribute_file(abac_context_t *ctx, char *filename) {
    int ret, add_ret;
    abac_list_t *cred_list=abac_list_new(); // could be more than 1
    abac_credential_t *cred;

    assert(ctx != NULL); assert(filename != NULL);

    ret = abac_verifier_load_attribute_cert_file(ctx->id_certs, filename, cred_list, ctx->keymap);

    if (ret == ABAC_CERT_SUCCESS) {
        int size = abac_list_size(cred_list);
        if(size) {
            abac_list_foreach(cred_list, cred,
                add_ret = abac_graph_add_credential(ctx->graph, cred);
                assert(add_ret != ABAC_GRAPH_CRED_INVALID);
                abac_credential_free(cred);
            );
        }
    }
    abac_list_free(cred_list);
    return ret;
}

/**
 * Load an attribute cert from a chunk.
 */
int abac_context_load_attribute_chunk(abac_context_t *ctx, abac_chunk_t cert_chunk) {
    int ret, add_ret;
    abac_list_t  *cred_list=abac_list_new(); // could be more than 1
    abac_credential_t *cred;

    assert(ctx != NULL);

    ret = abac_verifier_load_attribute_cert_chunk(ctx->id_certs, cert_chunk, cred_list, ctx->keymap);
    if (ret == ABAC_CERT_SUCCESS) {
        int size = abac_list_size(cred_list);
        if(size) {
            abac_list_foreach(cred_list, cred,
                add_ret = abac_graph_add_credential(ctx->graph, cred);
                assert(add_ret != ABAC_GRAPH_CRED_INVALID);
                abac_credential_free(cred);
            );
            abac_list_free(cred_list);
        }
    }

    return ret;
}

#define ID_PAT "/*_ID.{der,pem}"
#define ATTR_PAT "/*_attr.xml"

static int is_regular_file(char *filename)
{
   struct stat sb;
   if(stat(filename,&sb) == -1)
       return 0;
   if((sb.st_mode & S_IFMT) == S_IFREG)
       return 1;
   return 0;
}

/**
 * Load a directory full of certs.
 */
void abac_context_load_directory(abac_context_t *ctx, char *path) {
    DIR *dp;
    struct dirent *ep;
    static char pathname[MAXPATHLEN];
     
    dp = opendir (path);
    if (dp != NULL) {
        while ((ep = readdir (dp))) {
	    snprintf(pathname,MAXPATHLEN, "%s/%s", path, ep->d_name);
            if(is_regular_file(pathname)) {
                int ret = abac_context_load_id_file(ctx, pathname);
                if (ret == ABAC_CERT_SUCCESS) {
                    continue;
                }
                ret = abac_context_load_attribute_file(ctx, pathname);
            }
        }
        (void) closedir (dp);
    } else fprintf(stderr, "abac_load_directory, Couldn't open the directory\n");
}

/**
 * Run a query on the data in an abac context. Returns a NULL-terminated array
 * of abac_credential_t. Success/failure in *success.
 */
abac_credential_t **abac_context_query(abac_context_t *ctx, char *role, char *principal, int *success) {
    abac_credential_t **credentials = NULL, *cur;
    int i = 0;

    assert(ctx != NULL); assert(role != NULL); assert(principal != NULL); assert(success != NULL);

    abac_graph_t *result_graph = abac_graph_query(ctx->graph, role, principal);
    abac_list_t *result = abac_graph_credentials(result_graph);

    abac_graph_free(result_graph);

    int size = abac_list_size(result);
    if (size > 0)
        *success = 1;

    // if there is no actual path, return everything that can reach the role
    else {
        *success = 0;
        abac_list_free(result);

	// TODO: This can probably be better, but it now returns an
	// approximation of a partial proof.  It returns all the attributes the
	// principal can reach and all the attributes that will lead to a
	// success.

	/* Get all the attributes of the principal.  This calls sub-queries to
	 * flesh out the indirect proofs. */
        result_graph = abac_graph_principal_creds(ctx->graph, principal);

	/* This gets all the attributes linked to the target en route to the
	 * principal. */
        result = abac_graph_postorder_credentials(ctx->graph, role);

	/* Merge responses */
        int add_ret;
	abac_list_foreach(result, cur,
	    add_ret=abac_graph_add_credential(result_graph, cur);
            assert(add_ret != ABAC_GRAPH_CRED_INVALID);
            abac_credential_free(cur);
	);
        abac_list_free(result);
	abac_graph_derive_links(result_graph);

	result = abac_graph_credentials(result_graph);
	abac_graph_free(result_graph);

        size = abac_list_size(result);
    }

    // make the array (leave space to NULL terminate it)
    //      n.b., even if the list is empty, we still return an array that
    //            only contains the NULL terminator
    credentials = abac_xmalloc(sizeof(abac_credential_t *) * (size + 1));
    abac_list_foreach(result, cur,
        credentials[i++] = cur;
    );
    credentials[i] = NULL;

    abac_list_free(result);

    return credentials;
}


/**
 * A NULL-terminated array of all the credentials in the context.
 */
abac_credential_t **abac_context_credentials(abac_context_t *ctx) {
    abac_credential_t *cred;
    int i = 0;

    assert(ctx != NULL);

    abac_list_t *cred_list = abac_graph_credentials(ctx->graph);
    int size = abac_list_size(cred_list);

    abac_credential_t **credentials = abac_xmalloc(sizeof(abac_credential_t *) * (size + 1));
    abac_list_foreach(cred_list, cred,
        credentials[i++] = cred;
    );
    credentials[i] = NULL;

    abac_list_free(cred_list);

/* EXTRA: print out a list of principal stored within the context.. */
    if(0) {
        abac_id_cert_t **ilist=abac_context_principals(ctx);
        abac_id_cert_t *cert;
        if (ilist != NULL)
            for (i = 0; ilist[i] != NULL; ++i) {
                cert = ilist[i];
                printf("id[%d] %s\n",i, abac_id_cert_keyid(cert));
            }
        abac_context_id_credentials_free(ilist);
    }

    return credentials;
}

/*
 * Replace known keyids with their nicknames (mnemonic names).  If a non-NULL
 * string is returned it needs to be freed by the caller.
 */
char *abac_context_expand_key(abac_context_t *ctxt, char *s ) {
    if ( ctxt->keymap ) 
	return abac_keyid_map_expand_key(ctxt->keymap, s);
    else
	return NULL;
}

/*
 * Replace known nicknames(mnemonic names)  with their keyids.  If a non-NULL
 * string is returned it needs to be freed by the caller.
 */
char *abac_context_expand_nickname(abac_context_t *ctxt, char *s ) {
    if ( ctxt->keymap ) 
	return abac_keyid_map_expand_nickname(ctxt->keymap, s);
    else
	return NULL;
}

/*
 * Add a nickname to the context.  The keyid must be known to the context.  If
 * the nickname is in use, it is disambiguated.  Call abac_context_expand_key
 * to see the assigned name if that is required.  Existing nickname for keyid
 * is overwritten.  Returns true if the change was successful.
 */
int abac_context_set_nickname(abac_context_t *ctxt, char *key, char*nick) {
    char *p = NULL;

    if ( !ctxt->keymap) return 0;
    /* Make sure we know the key.  Free the returned nickname */
    if ( !(p = abac_keyid_map_key_to_nickname(ctxt->keymap, key))) return 0;
    else free(p);

    abac_keyid_map_remove_keyid(ctxt->keymap, key);
    return abac_keyid_map_add_nickname(ctxt->keymap, key, nick);
}

/*
 * Get direct access to the context's keyid mapping.  Used internally.  This
 * does not make a reference to the map, use abac_keyid_map_dup if that is
 * required.
 */
abac_keyid_map_t *abac_context_get_keyid_map(abac_context_t *ctxt) {
    return ctxt->keymap;
}


/**
 * A NULL-terminated array of all the principals in the context.
 */
abac_id_cert_t **abac_context_principals(abac_context_t *ctx)
{
    abac_id_cert_t **principals = NULL;
    assert(ctx != NULL);

    int size = abac_list_size(ctx->id_certs);

    // make the array (leave space to NULL terminate it)
    //      n.b., even if the list is empty, we still return an array that
    //            only contains the NULL terminator
    principals = abac_xmalloc(sizeof(abac_id_cert_t *) * (size + 1));
    int i = 0;
    abac_id_cert_t *id_cert;
    abac_list_foreach(ctx->id_certs, id_cert,
        principals[i]=abac_id_cert_dup(id_cert);
        i++;
    );
    principals[i] = NULL;

    return principals;
}


/**
 * Frees a NULL-terminated list of credentials.
 */
void abac_context_credentials_free(abac_credential_t **credentials) {
    int i;

    if (credentials == NULL)
        return;

    for (i = 0; credentials[i] != NULL; ++i)
        abac_credential_free(credentials[i]);
    free(credentials);
}

/**
 * Frees a NULL-terminated list of id credentials 
 */
void abac_context_id_credentials_free(abac_id_cert_t **id_credentials) {
    int i;

    if (id_credentials == NULL)
        return;

    for (i = 0; id_credentials[i] != NULL; ++i) {
        abac_id_cert_free(id_credentials[i]);
    }
    free(id_credentials);
}


