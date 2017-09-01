#ifndef __LIST_H__
#define __LIST_H__

#include "utlist.h"

typedef struct _abac_list_t abac_list_t;
typedef struct _abac_list_element_t abac_list_element_t;

struct _abac_list_element_t {
    void *ptr;
    abac_list_element_t *prev, *next;
};

struct _abac_list_t {
    abac_list_element_t *elts;
    int size;
};

abac_list_t *abac_list_new(void);
void abac_list_add(abac_list_t *list, void *elt);
int abac_list_remove(abac_list_t *list, void *elt);
int abac_list_size(abac_list_t *list);
void abac_list_free(abac_list_t *list);

#define abac_list_foreach(LIST, CURRENT, BODY) do {  \
    abac_list_element_t *_elt;                  \
    DL_FOREACH(LIST->elts, _elt) {              \
        CURRENT = (typeof(CURRENT))_elt->ptr;   \
        BODY                                    \
    }                                           \
} while (0)

#endif /* __LIST_H__ */
