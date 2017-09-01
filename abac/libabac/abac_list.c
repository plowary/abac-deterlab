#include <stdlib.h>

#include "abac_list.h"
#include "abac_util.h"

abac_list_t *abac_list_new(void) {
    abac_list_t *ret = abac_xmalloc(sizeof(abac_list_t));
    ret->elts = NULL;
    ret->size = 0;
    return ret;
}

void abac_list_add(abac_list_t *list, void *elt) {
    abac_list_element_t *new_element = abac_xmalloc(sizeof(abac_list_element_t));

    new_element->ptr = elt;
    DL_APPEND(list->elts, new_element);
    ++list->size;
}

int abac_list_remove(abac_list_t *list, void *elt) {
    abac_list_element_t *cur;

    // iterate the list, remove the item if we find it
    DL_FOREACH(list->elts, cur) {
        if (cur->ptr == elt) {
            DL_DELETE(list->elts, cur);
            free(cur);
            --list->size;
            return 1;
        }
    }

    // reutrn false if we don't
    return 0;
}

int abac_list_size(abac_list_t *list) {
    return list->size;
}

void abac_list_free(abac_list_t *list) {
    abac_list_element_t *elt, *tmp;

    // free everthing in the list
    DL_FOREACH_SAFE(list->elts, elt, tmp) {
        DL_DELETE(list->elts, elt);
        free(elt);
    }

    // free the list
    free(list);
}
