#include <stdlib.h>

#include "abac_set.h"
#include "abac_util.h"

#include "uthash.h"

typedef struct _abac_set_element_t {
    char *key;
    UT_hash_handle hh;
} abac_set_element_t;

struct _abac_set_t {
    abac_set_element_t *elts;
    int size;
};

/**
 * Create a new struct.
 */
abac_set_t *abac_set_new(void) {
    abac_set_t *ret = abac_xmalloc(sizeof(abac_set_t));
    ret->elts = NULL;
    ret->size = 0;
    return ret;
}

/**
 * Add an item to the set, returns true if it doesn't exist.
 */
int abac_set_add(abac_set_t *set, char *value) {
    abac_set_element_t *elt;

    HASH_FIND_STR(set->elts, value, elt);
    if (elt) return 0; // already exists

    elt = abac_xmalloc(sizeof(abac_set_element_t));
    elt->key = abac_xstrdup(value);
    HASH_ADD_KEYPTR(hh, set->elts, elt->key, strlen(elt->key), elt);

    ++set->size;

    return 1;
}

/**
 * Does the set contain the value.
 */
int abac_set_contains(abac_set_t *set, char *value) {
    abac_set_element_t *elt;

    HASH_FIND_STR(set->elts, value, elt);
    return elt != NULL;
}

/**
 * Return a list of the set's elements.
 */
abac_list_t *abac_set_elements(abac_set_t *set) {
    abac_set_element_t *elt;
    abac_list_t *ret = abac_list_new();

    for (elt = set->elts; elt != NULL; elt = elt->hh.next) {
        char *next = elt->key;
        abac_list_add(ret, next);
    }

    return ret;
}

/**
 * Returns the number of elements in the set.
 */
int abac_set_size(abac_set_t *set) {
    return set->size;
}

/**
 * Takes the intersection of l and r.
 */
void abac_set_intersect(abac_set_t *l, abac_set_t *r) {
    abac_set_element_t *elt, *next;

    for (elt = l->elts; elt != NULL; elt = next) {
        next = elt->hh.next;

        // if the rhs doesn't contain this item, remove it
        if (!abac_set_contains(r, elt->key)) {
            HASH_DEL(l->elts, elt);
            free(elt->key);
            free(elt);
            --l->size;
        }
    }
}

/**
 * Destroy a set.
 */
void abac_set_free(abac_set_t *set) {
    abac_set_element_t *elt;

    while ((elt = set->elts) != NULL) {
        HASH_DEL(set->elts, elt);
        free(elt->key);
        free(elt);
    }

    free(set);
}
