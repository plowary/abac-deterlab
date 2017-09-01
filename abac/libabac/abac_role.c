#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "abac.h"
#include "abac_list.h"
#include "abac_util.h"

// typedef'd in role.h
struct _abac_role_t {
    char *principal;
    char *linked_role;
    char *role_name;

    char *string;
    char *linked;
    /* Copy of the last string printed with abac_role_short_string */
    char *short_string;

    abac_list_t *prereqs;

    int refcount;
};

/**
 * Create a new principal and initialize it.
 */
abac_role_t *abac_role_principal_new(char *principal) {
    assert(principal != NULL);

    abac_role_t *role;

    if (strlen(principal) == 0)
        return NULL;

    role = abac_xmalloc(sizeof(abac_role_t));

    role->principal = abac_xstrdup(principal);
    role->role_name = NULL;
    role->linked_role = NULL;

    role->string = abac_xstrdup(principal);
    role->short_string = NULL;
    role->linked = NULL;
    role->prereqs = NULL;

    role->refcount = 1;

    return role;
}

/**
 * Create a new role and initialize it.
 */
abac_role_t *abac_role_role_new(char *principal, char *role_name) {
    assert(principal != NULL);
    assert(role_name != NULL);

    abac_role_t *role;

    if (strlen(principal) == 0 || strlen(role_name) == 0)
        return NULL;

    role = abac_xmalloc(sizeof(abac_role_t));

    role->principal = abac_xstrdup(principal);
    role->role_name = abac_xstrdup(role_name);
    role->linked_role = NULL;

    int prin_len = strlen(principal);
    int role_len = strlen(role_name);

    role->string = abac_xmalloc(prin_len + 1 + role_len + 1);
    memcpy(role->string, principal, prin_len);
    role->string[prin_len] = '.';
    memcpy(role->string + prin_len + 1, role_name, role_len);
    role->string[prin_len + 1 + role_len] = 0;
    role->short_string = NULL;

    role->linked = NULL;
    role->prereqs = NULL;

    role->refcount = 1;

    return role;
}

/**
 * Created a new linking role and initialize it.
 */
abac_role_t *abac_role_linking_new(char *principal, char *linked, char *role_name) {
    assert(principal != NULL);
    assert(linked != NULL);
    assert(role_name != NULL);

    abac_role_t *role;

    if (strlen(principal) == 0 || strlen(linked) == 0 || strlen(role_name) == 0)
        return NULL;

    role = abac_xmalloc(sizeof(abac_role_t));

    role->principal = abac_xstrdup(principal);
    role->linked_role = abac_xstrdup(linked);
    role->role_name = abac_xstrdup(role_name);

    int prin_len = strlen(principal);
    int link_len = strlen(linked);
    int role_len = strlen(role_name);

    role->string = abac_xmalloc(prin_len + 1 + link_len + 1 + role_len + 1);

    memcpy(role->string, principal, prin_len);
    role->string[prin_len] = '.';
    memcpy(role->string + prin_len + 1, linked, link_len);
    role->string[prin_len + 1 + link_len] = 0;

    // hack: linked role is first two parts of full string
    role->linked = abac_xstrdup(role->string);

    role->string[prin_len + 1 + link_len] = '.';
    memcpy(role->string + prin_len + 1 + link_len + 1, role_name, role_len);
    role->string[prin_len + 1 + link_len + 1 + role_len] = 0;
    role->short_string = NULL;

    role->prereqs = NULL;

    role->refcount = 1;

    return role;
}

/**
 * Create an intersection role.
 */
abac_role_t *abac_role_intersection_new(char *name, abac_list_t *prereqs) {
    abac_role_t *role = abac_xmalloc(sizeof(abac_role_t));

    role->principal = role->linked_role = role->role_name = NULL;
    role->linked = NULL;

    role->string = abac_xstrdup(name);
    role->prereqs = prereqs;
    role->short_string = NULL;

    role->refcount = 1;

    return role;
}

/**
 * Decrease a role's reference count, freeing it when it reaches 0.
 */
void abac_role_free(abac_role_t *role) {
    if (role == NULL)
        return;

    --role->refcount;
    if (role->refcount > 0)
        return;

    free(role->principal);
    free(role->linked_role);
    free(role->role_name);

    free(role->string);
    free(role->linked);

    if (role->prereqs != NULL) {
        abac_role_t *cur;
        abac_list_foreach(role->prereqs, cur,
            abac_role_free(cur);
        );
        abac_list_free(role->prereqs);
    }

    if ( role->short_string) 
	free(role->short_string);
    free(role);
}

/**
 * Create a non-intersecting role from a string. Handles principals, roles,
 * and linking roles.
 */
static abac_role_t *_abac_single_role_from_string(char *string) {
    int num_dots = 0;
    char *dot = string;
    abac_role_t *ret = NULL;

    // count the dots
    while ((dot = strchr(dot, '.')) != NULL) {
        ++num_dots;
        ++dot;
    }

    // no dots: easy case, principal
    if (num_dots == 0) {
        ret = abac_role_principal_new(string);
    }

    // a role has exactly 1 dot
    else if (num_dots == 1) {
        char *principal = string;

        // terminate the principal part
        dot = strchr(principal, '.');
        *dot = 0;

        // role name comes after the dot
        char *role_name = dot + 1;

        // create the role (if possible)
        ret = abac_role_role_new(string, role_name);
    }

    // a linked role has 2 dots
    else if (num_dots == 2) {
        char *principal = string;

        // terminate the principal part
        dot = strchr(principal, '.');
        *dot = 0;

        // linked name is next, terminate it
        char *linked = dot + 1;
        dot = strchr(linked, '.');
        *dot = 0;

        // role name is last, already terminated
        char *role_name = dot + 1;

        ret = abac_role_linking_new(principal, linked, role_name);
    }

    // more than two dots: return NULL

    return ret;
}

/**
 * Create a role from a string. Handles intersecting and normal roles.
 */
abac_role_t *abac_role_from_string(char *istring) {
    abac_list_t *prereqs = NULL;
    abac_role_t *ret = NULL, *role;
    char *roles[256];
    int num_roles, i;
    char *string;

    char *original = istring;

    // make a copy so we can mess with it
    string = abac_xstrdup(istring);

    // split the string (in case of an intersection num_roles > 1)
    num_roles = 256;
    abac_split(string, " & ", roles, &num_roles);

    // normal role: 
    if (num_roles == 1) {
        ret = _abac_single_role_from_string(string);

    } else {
        prereqs = abac_list_new();

        for (i = 0; i < num_roles; ++i) {
            // make sure the tail role is valid
            role = abac_role_from_string(roles[i]);
            if (role == NULL)
                goto error;

            abac_list_add(prereqs, role);
        }

        ret = abac_role_intersection_new(original, prereqs);
    }

    free(string);
    return ret;

error:
    if (prereqs != NULL) {
        abac_list_foreach(prereqs, role,
            abac_role_free(role);
        );
        abac_list_free(prereqs);
    }
    free(string);

    return NULL;
}


/**
 * Increase a role's reference count.
 */
abac_role_t *abac_role_dup(abac_role_t *role) {
    assert(role != NULL);

    ++role->refcount;
    return role;
}

/**
 * True if a role is a principal.
 */
int abac_role_is_principal(abac_role_t *role) {
    assert(role != NULL);
    return role->role_name == NULL && role->linked_role == NULL && role->prereqs == NULL;
}

/**
 * True if a role is a role.
 */
int abac_role_is_role(abac_role_t *role) {
    assert(role != NULL);
    return role->role_name != NULL && role->linked_role == NULL && role->prereqs == NULL; 
}

/**
 * True if a role is a linked role.
 */
int abac_role_is_linking(abac_role_t *role) {
    assert(role != NULL);
    return role->linked_role != NULL;
}

/**
 * True if a role is an intersection.
 */
int abac_role_is_intersection(abac_role_t *role) {
    assert(role != NULL);
    return role->prereqs != NULL;
}

/**
 * Returns the string representation of the role.
 */
char *abac_role_string(abac_role_t *role) {
    assert(role != NULL);
    return role->string;
}

/**
 * Returns the string representation of the role, with keyids converted to
 * mnemonic names where possible.  The return value must *not* be freed.
 */
char *abac_role_short_string(abac_role_t *role, abac_context_t *ctxt) {
    assert(role != NULL);
    if (!ctxt) return role->string;
    if ( role->short_string) 
	free(role->short_string);
    role->short_string = abac_context_expand_key(ctxt, role->string);
    return role->short_string;
}

/**
 * Returns the name of a role. If the role is A.r1 then return r1. If the role
 * is A.r1.r2 then return r2.
 */
char *abac_role_role_name(abac_role_t *role) {
    assert(role != NULL);
    return role->role_name;
}

/**
 * Returns the linked part of a linking role. For instance, if the role is
 * A.r1.r2, this returns A.r1.
 */
char *abac_role_linked_role(abac_role_t *role) {
    assert(role != NULL);
    return role->linked;
}

/**
 * Returns the linkinged part of a linking role. For instance, if the role is
 * A.r1.r2, this returns r1.
 */
char *abac_role_linking_role(abac_role_t *role) {
    assert(role != NULL);
    return role->linked_role;
}

/**
 * Returns the principal part of a role. The stuff before the first dot.
 */
char *abac_role_principal(abac_role_t *role) {
    assert(role != NULL);
    return role->principal;
}

/**
 * Returns the prereqs of an intersection.
 */
abac_list_t *abac_role_prereqs(abac_role_t *role) {
    assert(role != NULL);
    return role->prereqs;
}

/**
 * Build an attribute key from head and tail roles. Static.
 */
#define ROLE_SEPARATOR " <- "
char *abac_role_attr_key(abac_role_t *head_role, abac_role_t *tail_role) {
    char *head = abac_role_string(head_role);
    int head_len = strlen(head);

    char *tail = abac_role_string(tail_role);
    int tail_len = strlen(tail);

    int sep_len = sizeof(ROLE_SEPARATOR) - 1;

    // "head <- tail"
    char *ret = abac_xmalloc(head_len + tail_len + sep_len + 1);
    memcpy(ret, head, head_len);
    memcpy(ret + head_len, ROLE_SEPARATOR, sep_len);
    memcpy(ret + head_len + sep_len, tail, tail_len);
    ret[head_len + sep_len + tail_len] = 0;

    return ret;
}
