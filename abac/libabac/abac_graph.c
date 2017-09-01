
/* abac_graph.c */

#include <assert.h>
#include <stdlib.h>

#include "abac_graph.h"

#include "abac_set.h"
#include "abac_util.h"

#include "uthash.h"

// vertex
struct _abac_vertex_t {
    abac_role_t *role;
    char *name;
    int refcount;

    abac_list_t *edges;
    abac_list_t *reverse_edges;

    // only relevant to intersection edges
    abac_list_t *prereqs;

    UT_hash_handle hh;
};

// edge
typedef struct _abac_edge_t {
    int refcount;
    abac_vertex_t *vertex;
    abac_vertex_t *reverse_vertex;
    abac_credential_t *credential;
} abac_edge_t;

// derived edge
typedef struct _abac_derived_key_t {
    abac_vertex_t *head;
    abac_edge_t *tail;
} abac_derived_key_t;

typedef struct _abac_derived_t {
    abac_derived_key_t key;
    UT_hash_handle hh;
} abac_derived_t;

// graph
struct _abac_graph_t {
    abac_vertex_t *vertices;
    abac_derived_t *derived;
    int dirty;
};

// ugghhhghhhghh need this for intersections
abac_list_t *abac_role_prereqs(abac_role_t *);

static abac_vertex_t *_dup_vertex(abac_vertex_t *v);
int abac_graph_add_credential(abac_graph_t *graph, abac_credential_t *cred);

/**
 * Create a new graph.
 */
abac_graph_t *abac_graph_new(void) {
    abac_graph_t *graph = abac_xmalloc(sizeof(abac_graph_t));

    graph->vertices = NULL;
    graph->derived = NULL;
    graph->dirty = 0;

    return graph;
}

/**
 * Deep copy a graph.
 */
abac_graph_t *abac_graph_dup(abac_graph_t *graph) {
    abac_vertex_t *vertex;
    abac_edge_t *edge;

    abac_graph_t *clone = abac_graph_new();

    // copy the vertices edge by edge
    for (vertex = graph->vertices; vertex != NULL; vertex = vertex->hh.next)
        abac_list_foreach(vertex->edges, edge,
            // only copy non-derived edges
            if (edge->credential != NULL)
                abac_graph_add_credential(clone, edge->credential);
        );

    return clone;
}
/**
 * Add a vertex to the graph. Should only be called by
 * abac_graph_add_credential. This returns an existing vertex 
 * or a new vertex with a refcount of 1.  Either way it gets and
 * references the vertex.
 */
static abac_vertex_t *_get_vertex(abac_graph_t *graph, abac_role_t *role) {
    abac_vertex_t *vertex;
    char *string;
    
    string =abac_role_string(role);
    HASH_FIND_STR(graph->vertices, string, vertex);

    // add the vertex if it doesn't exist
    if (vertex == NULL) {
        vertex = abac_xmalloc(sizeof(abac_vertex_t));
        vertex->refcount = 1;
        vertex->role = abac_role_dup(role);
        vertex->name = abac_role_string(vertex->role);

        // create the list of edges
        vertex->edges = abac_list_new();
        vertex->reverse_edges = abac_list_new();

        // for intersections, always NULL on normal vertices
        if (abac_role_is_intersection(role)) {
            abac_role_t *prereq;
            vertex->prereqs = abac_list_new();

            // add each prereq to the vertex (dup'ed)
            abac_list_foreach(abac_role_prereqs(role), prereq,
                abac_vertex_t *tail_vertex = _get_vertex(graph, prereq);
                abac_list_add(vertex->prereqs, _dup_vertex(tail_vertex));
            );
        }

        // normal edges have no prereqs
        else
            vertex->prereqs = NULL;

        // add it to the vertices
        HASH_ADD_KEYPTR(hh, graph->vertices, vertex->name, strlen(vertex->name), vertex);

    } 

    return vertex;
}

/* forward decl */
static void _free_edge(abac_edge_t *edge);

/*
 * Reduce the vertex reference count and free it if this is the last reference
 */
static void _free_vertex(abac_vertex_t *vertex) {
    abac_edge_t *edge=NULL;
    abac_vertex_t *pre=NULL;

    --vertex->refcount;

    if ( vertex->refcount > 0) return;

    abac_role_free(vertex->role);

    abac_list_foreach(vertex->edges, edge,
        _free_edge(edge);
    );
    abac_list_free(vertex->edges);

    abac_list_foreach(vertex->reverse_edges, edge,
        _free_edge(edge);
    );
    abac_list_free(vertex->reverse_edges);

    // Free the prereqs
    if (vertex->prereqs != NULL) {
        abac_list_foreach(vertex->prereqs, pre,
            if (pre != NULL) {
                _free_vertex(pre);
            }
        );
        abac_list_free(vertex->prereqs);
    }

    free(vertex);
}

/*
 * Increment vertex reference count
 */
static abac_vertex_t *_dup_vertex(abac_vertex_t *v) {
    v->refcount++;
    return v;
}


/*
 * create a new edge from the given head, tail and credential
 */

static abac_edge_t *_get_edge(abac_vertex_t *h, abac_vertex_t *t,
        abac_credential_t *c) {

    /* An edge does not own it's vertices.  Do not delete them from an edge
     * reference. */
    abac_edge_t *edge = abac_xmalloc(sizeof(abac_edge_t));
    edge->refcount = 1;
    edge->vertex = t;
    edge->reverse_vertex = h;
    /* Don't dup a null credential */
    edge->credential = (c) ? abac_credential_dup(c): NULL;

    return edge;
}


/**
 * Increment the reference count
 */
static abac_edge_t *_dup_edge(abac_edge_t *e) {
    e->refcount++;
    return e;
}

/**
 * Decerement the refcount and free it if this was the last reference.  NB
 * edges do not own teh vertices, so they must be deleted elsewhere.
 */
static void _free_edge(abac_edge_t *edge) {
    assert(edge && edge->refcount > 0);
    if ( --edge->refcount > 0) return;
    if (edge->credential) abac_credential_free(edge->credential);
    free(edge);
}

/**
 * Add a credential to the credential graph.
 */
int abac_graph_add_credential(abac_graph_t *graph, abac_credential_t *cred) {
    abac_vertex_t *head_vertex, *tail_vertex;
    abac_edge_t *edge;

    assert(cred != NULL);

    abac_role_t *head = abac_credential_head(cred);
    abac_role_t *tail = abac_credential_tail(cred);

    // a valid credential must have a role for the head
    if (!abac_role_is_role(head)) return 0;

    head_vertex = _get_vertex(graph, head);
    tail_vertex = _get_vertex(graph, tail);

    // make sure we don't insert the same edge twice (ugh)
    abac_list_foreach(head_vertex->edges, edge,
        if (edge->vertex == tail_vertex) {
            return 0;
        }
    );

    // create the edge and add it
    edge = _get_edge(head_vertex, tail_vertex, cred);

    abac_list_add(head_vertex->edges, edge);
    abac_list_add(tail_vertex->reverse_edges, _dup_edge(edge));

    // must re-derive edges
    graph->dirty = 1;

    return 1;
}

// find the principals that have a role
static abac_set_t *_find_principals(abac_graph_t *graph, abac_vertex_t *start_vertex) {
    abac_set_t *principals = abac_set_new();

    abac_list_t *traversal = abac_graph_postorder(graph, start_vertex->role);
    abac_vertex_t *vertex;

    abac_list_foreach(traversal, vertex,
        if (abac_role_is_principal(vertex->role))
            abac_set_add(principals, abac_role_string(vertex->role));
    );

    abac_list_free(traversal);
    return principals;
}

// remove any derived edges from the graph
void _clear_derived(abac_graph_t *graph) {
    abac_derived_t *current;

    while (graph->derived) {
        current = graph->derived;

        HASH_DEL(graph->derived, current);

        abac_vertex_t *head = current->key.head;
        abac_edge_t *tail = current->key.tail;
        assert(tail->credential == NULL);

        // this can fail, but we assume the data structures are consistent
        abac_list_remove(head->edges, tail);
        abac_list_remove(tail->reverse_vertex->edges, tail);

        _free_edge(tail);
        free(current);
    }
}

// add a derived edge, returns 1 if added 0 if dup
static int _derived_edge(abac_graph_t *graph, abac_vertex_t *head, abac_vertex_t *tail) {
    abac_edge_t *edge;

    // don't add duplicate edges
    abac_list_foreach(head->edges, edge,
        if (edge->vertex == tail)
            return 0;
    );

    debug_printf("derived edge %s <- %s\n", head->name, tail->name);

    edge = _get_edge(head, tail, NULL);
    abac_list_add(head->edges, edge);
    abac_list_add(tail->reverse_edges, _dup_edge(edge));

    // add to list of derived edges
    abac_derived_t *derived = abac_xmalloc(sizeof(abac_derived_t));
    derived->key.head = head;
    derived->key.tail = edge;
    HASH_ADD(hh, graph->derived, key, sizeof(abac_derived_key_t), derived);

    return 1;
}

// find a vertex by name
abac_vertex_t *_find_vertex(abac_graph_t *graph, char *name) {
    abac_vertex_t *ret = NULL;
    HASH_FIND_STR(graph->vertices, name, ret);
    return ret;
}

/**
 * Single iteration of deriving new edges. Returns the number of new edges
 * added.
 */
static int _derive_links_iter(abac_graph_t *graph) {
    int count = 0;
    abac_vertex_t *vertex;

    for (vertex = graph->vertices; vertex != NULL; vertex = vertex->hh.next) {
        // intersection
        if (abac_role_is_intersection(vertex->role)) {
            // for each prereq edge:
            //     find principals that have the edge
            // find intersection of all sets
            // for each principal B in intersection:
            //     add link

            char *name;
            abac_vertex_t *prereq;
            abac_set_t *principals = NULL;

            abac_list_foreach(vertex->prereqs, prereq,
                abac_set_t *cur = _find_principals(graph, prereq);

                if (principals == NULL)
                    principals = cur;
                else {
                    abac_set_intersect(principals, cur);
                    abac_set_free(cur);
                }

                if (abac_set_size(principals) == 0)
                    goto isect_done;
            );

            abac_list_t *prin_names = abac_set_elements(principals);
            abac_list_foreach(prin_names, name,
                abac_vertex_t *principal = _find_vertex(graph, name);
                count += _derived_edge(graph, vertex, principal);
            );

            abac_list_free(prin_names);
isect_done:
            abac_set_free(principals);
        }

        // linking role
        else if (abac_role_is_linking(vertex->role)) {
            // linking roles take the form A.r1.r2
            char *A_r1 = abac_role_linked_role(vertex->role);
            char *r2 = abac_role_role_name(vertex->role);

            // find the linked role in the graph
            abac_vertex_t *A_r1_vertex;
            HASH_FIND_STR(graph->vertices, A_r1, A_r1_vertex);
            if (A_r1_vertex == NULL)
                continue;

            // find the principals that have A.r1
            abac_set_t *principals = _find_principals(graph, A_r1_vertex);
            char *B;

            abac_list_t *elts = abac_set_elements(principals);

            // and add a link for each B.r2 to A.r1.r2
            abac_list_foreach(elts, B,
                int B_len = strlen(B);
                int r2_len = strlen(r2);

                // create the string B.r2, thx C
                char *B_r2 = malloc(B_len + r2_len + 2);
                memcpy(B_r2, B, B_len);
                B_r2[B_len] = '.';
                memcpy(B_r2 + B_len + 1, r2, r2_len);
                B_r2[B_len + r2_len + 1] = 0;

                // add an edge if the principal's granted it to someone
                abac_vertex_t *B_r2_vertex = _find_vertex(graph, B_r2);
                if (B_r2_vertex) {
                    debug_printf("adding edge from %s to %s\n", B_r2, abac_role_string(vertex->role));
                    count += _derived_edge(graph, vertex, B_r2_vertex);
                }

#ifdef DEBUG
                debug_printf("    incoming edges for %s\n", abac_role_string(vertex->role));
                abac_edge_t *cur;
                abac_list_foreach(vertex->edges, cur,
                    debug_printf("        %s (%s)\n", abac_role_string(cur->vertex->role), cur->vertex->name);
                );
#endif

                free(B_r2);
            );

            abac_list_free(elts);
            abac_set_free(principals);
        }
    }

    return count;
}

/**
 * Derive all implied edges in the graph. These can come from linking roles
 * and intersections.
 *
 * We have to do it iteratively because derived edges can imply new edges.
 */
void abac_graph_derive_links(abac_graph_t *graph) {
    if (!graph->dirty)
        return;

    // iterate as long as new links are derived
    while (_derive_links_iter(graph) > 0)
        ;

    graph->dirty = 0;
}

static void _reverse_order_recurse(abac_vertex_t *vertex, abac_set_t *seen, int preorder, abac_list_t *stack) {
    abac_edge_t *outgoing;

    // don't revisit nodes
    if (!abac_set_add(seen, abac_role_string(vertex->role)))
        return;

    if (preorder) {
        abac_list_add(stack, vertex);
    }

    // recurse along the incoming vertices
    abac_list_foreach(vertex->reverse_edges, outgoing,
        _reverse_order_recurse(outgoing->reverse_vertex, seen, preorder, stack);
    );

    if (!preorder) {
        abac_list_add(stack, vertex);
    }
}

static abac_list_t *_reverse_order(abac_graph_t *graph, abac_role_t *start, int preorder) {
    debug_printf("%sorder at %s\n", preorder ? "pre" : "post", abac_role_string(start));


    abac_vertex_t *start_vertex = _get_vertex(graph, start);

    abac_set_t *seen = abac_set_new();

    // create the return list
    abac_list_t *stack = abac_list_new();

    _reverse_order_recurse(start_vertex, seen, preorder, stack);

    abac_set_free(seen);


    return stack;
}

static void _order_recurse(abac_vertex_t *vertex, abac_set_t *seen, int preorder, abac_list_t *stack) {
    abac_edge_t *incoming;

    // don't revisit nodes
    if (!abac_set_add(seen, abac_role_string(vertex->role)))
        return;

    if (preorder) {
        abac_list_add(stack, vertex);
    }

    // recurse along the incoming vertices
    abac_list_foreach(vertex->edges, incoming,
        _order_recurse(incoming->vertex, seen, preorder, stack);
    );

    if (!preorder) {
        abac_list_add(stack, vertex);
    }
}

static abac_list_t *_order(abac_graph_t *graph, abac_role_t *start, int preorder) {
    debug_printf("%sorder at %s\n", preorder ? "pre" : "post", abac_role_string(start));

    abac_vertex_t *start_vertex = _get_vertex(graph, start);

    abac_set_t *seen = abac_set_new();

    // create the return list
    abac_list_t *stack = abac_list_new();

    _order_recurse(start_vertex, seen, preorder, stack);

    abac_set_free(seen);

    return stack;
}

abac_list_t *abac_graph_postorder(abac_graph_t *graph, abac_role_t *start) {
    return _order(graph, start, 0);
}

/**
 * Postorder traverse the graph and return all the credentials within.
 */
abac_list_t *abac_graph_postorder_credentials(abac_graph_t *graph, char *start) {
    abac_vertex_t *vertex;
    abac_edge_t *incoming;

    // get the postorder of vertices
    abac_role_t *role = abac_role_from_string(start);
    abac_list_t *order = abac_graph_postorder(graph, role);

    // go through the list and dup all the credentials
    abac_list_t *credentials = abac_list_new();
    abac_list_foreach(order, vertex,
        abac_list_foreach(vertex->edges, incoming,
            if (incoming->credential != NULL) {
                abac_list_add(credentials, abac_credential_dup(incoming->credential));
            }
        );
    );

    abac_role_free(role);
    abac_list_free(order);

    return credentials;
}


abac_list_t *abac_graph_postorder_reverse(abac_graph_t *graph, abac_role_t *start) {
    return _reverse_order(graph, start, 0);
}

/**
 * Postorder traverse the graph and return all the credentials within.
 */
abac_list_t *abac_graph_postorder_reverse_credentials(abac_graph_t *graph, char *start) {
    abac_vertex_t *vertex;
    abac_edge_t *outgoing;

    // get the postorder of vertices
    abac_role_t *role = abac_role_from_string(start);
    abac_list_t *order = abac_graph_postorder_reverse(graph, role);

    // go through the list and dup all the credentials
    abac_list_t *credentials = abac_list_new();

    abac_list_foreach(order, vertex,
        abac_list_foreach(vertex->reverse_edges, outgoing,
            if (outgoing->credential != NULL) {
                abac_list_add(credentials, abac_credential_dup(outgoing->credential));
            }
        );
    );

    abac_role_free(role);
    abac_list_free(order);

    return credentials;
}

static void _query(abac_graph_t *graph, char *role_name, char *principal, abac_graph_t *return_graph) {
    abac_vertex_t *vertex;
    abac_edge_t *incoming;
    abac_role_t *role = abac_role_from_string(role_name);
    abac_role_t *prin_role = abac_role_from_string(principal);

    // give up on bogus roles
    if (role == NULL || prin_role == NULL) {
        abac_role_free(role);
        abac_role_free(prin_role);
        return;
    }

    abac_set_t *on_path = abac_set_new();
    abac_set_add(on_path, abac_role_string(prin_role));

    abac_list_t *traversal = abac_graph_postorder(graph, role);
    abac_list_foreach(traversal, vertex,
        abac_role_t *role = vertex->role;

        abac_list_foreach(vertex->edges, incoming,
            abac_role_t *incoming_role = incoming->vertex->role;

            if (!abac_set_contains(on_path, abac_role_string(incoming_role)))
                continue;

            abac_set_add(on_path, abac_role_string(role));

            // get implying edges for intersection vertices
            if (abac_role_is_intersection(role)) {
                abac_vertex_t *prereq;
                abac_list_foreach(vertex->prereqs, prereq,
                    _query(graph, prereq->name, principal, return_graph);
                );
            }

            // recursively find linked roles
            else if (abac_role_is_linking(role)) {
                char *linked_role = abac_role_linked_role(role);
                char *principal = abac_role_principal(incoming_role);

                _query(graph, linked_role, principal, return_graph);
            }

            // add non-derived edges to the proof graph
            else
                abac_graph_add_credential(return_graph, incoming->credential);
        );
    );

    abac_list_free(traversal);
    abac_set_free(on_path);
    abac_role_free(role);
    abac_role_free(prin_role);
}

abac_graph_t *abac_graph_query(abac_graph_t *graph, char *role, char *principal) {
    abac_graph_derive_links(graph);

    abac_graph_t *return_graph = abac_graph_new();
    _query(graph, role, principal, return_graph);
    abac_graph_derive_links(return_graph);
    return return_graph;
}

abac_graph_t *abac_graph_principal_creds(abac_graph_t *graph, char *principal) {
    abac_graph_derive_links(graph);
    abac_graph_t *result_graph = abac_graph_new();

    abac_list_t *result = abac_graph_postorder_reverse_credentials(graph, 
	    principal);

    abac_credential_t *cur = NULL;
    int add_ret;
    abac_list_foreach(result, cur,
	add_ret=abac_graph_add_credential(result_graph, cur);
        assert(add_ret != ABAC_GRAPH_CRED_INVALID);
        abac_credential_free(cur);
    );
    abac_list_free(result);
    /* For each terminal role that the principal can reach, roll a proof into
       the result_graph. */

    abac_vertex_t *vertex = NULL;
    for (vertex = result_graph->vertices; vertex != NULL; 
	    vertex = vertex->hh.next) {
	if ( abac_list_size(vertex->reverse_edges) == 0) 
	    _query(graph, vertex->name, principal, result_graph);
    }
    abac_graph_derive_links(result_graph);

    return result_graph;
}


/**
 * Get all the credentials (attribute/issuer cert pairs) from the graph.
 */
abac_list_t *abac_graph_credentials(abac_graph_t *graph) {
    abac_list_t *credentials = abac_list_new();

    abac_vertex_t *vertex;

    for (vertex = graph->vertices; vertex != NULL; vertex = vertex->hh.next) {
        abac_edge_t *edge;
        abac_list_foreach(vertex->edges, edge,
            if (edge->credential != NULL)
                abac_list_add(credentials, abac_credential_dup(edge->credential));
        );
    }

    return credentials;
}

void abac_graph_free(abac_graph_t *graph) {
    abac_vertex_t *vertex;

    // kill derived edges
    _clear_derived(graph);

    // delete vertices
    while ((vertex = graph->vertices) != NULL) {
        HASH_DEL(graph->vertices, vertex);
        _free_vertex(vertex);
    }

    free(graph);
}

abac_role_t *abac_vertex_role(abac_vertex_t *vertex) {
    return vertex->role;
}
