#ifndef __SET_H__
#define __SET_H__

#include "abac_list.h"

typedef struct _abac_set_t abac_set_t;

abac_set_t *abac_set_new(void);
int abac_set_add(abac_set_t *set, char *value);
int abac_set_contains(abac_set_t *set, char *value);
abac_list_t *abac_set_elements(abac_set_t *set);
int abac_set_size(abac_set_t *set);
void abac_set_intersect(abac_set_t *l, abac_set_t *r);
void abac_set_free(abac_set_t *set);

#endif /* __SET_H__ */
