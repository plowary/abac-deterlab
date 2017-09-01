#ifndef __GRAPH_H__
#define __GRAPH_H__

#include "abac.h"
#include "abac_list.h"
#include "abac_verifier.h"

#define ABAC_GRAPH_CRED_OK          0   // adding a credential succeeded
#define ABAC_GRAPH_CRED_INVALID     -1  // the credential was invalid
#define ABAC_GRAPH_CRED_DUP         -2  // the credential is already present in the graph

typedef struct _abac_graph_t abac_graph_t;
typedef struct _abac_vertex_t abac_vertex_t;

abac_graph_t *abac_graph_new(void);
abac_graph_t *abac_graph_dup(abac_graph_t *graph);

// returns a status as defined at the top of the file
int abac_graph_add_credential(abac_graph_t *graph, abac_credential_t *cred);
void abac_graph_derive_links(abac_graph_t *graph);
abac_list_t *abac_graph_postorder(abac_graph_t *graph, abac_role_t *start);
abac_list_t *abac_graph_postorder_credentials(abac_graph_t *graph, char *start);
abac_list_t *abac_graph_postorder_reverse(abac_graph_t *graph, abac_role_t *start);
abac_list_t *abac_graph_postorder_reverse_credentials(abac_graph_t *graph, char *start);
abac_graph_t *abac_graph_principal_creds(abac_graph_t *graph, char *principal);
abac_graph_t *abac_graph_query(abac_graph_t *graph, char *role, char *principal);
abac_list_t *abac_graph_credentials(abac_graph_t *graph);
void abac_graph_free(abac_graph_t *graph);

abac_role_t *abac_vertex_role(abac_vertex_t *vertex);

#endif /* __GRAPH_H__ */
