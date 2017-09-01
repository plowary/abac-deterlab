#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/types.h>
#include <stdlib.h>

#ifndef __ABAC_CHUNK_T__
#define __ABAC_CHUNK_T__
typedef struct _abac_chunk_t {
    unsigned char *ptr;
    int len;
} abac_chunk_t;

#endif /* __ABAC_CHUNK_T__ */

void abac_chunk_free(abac_chunk_t *);
int abac_chunk_null(abac_chunk_t *);
int abac_chunk_show(abac_chunk_t *);

void *abac_xmalloc(size_t);
char *abac_xstrdup(char *);
void *abac_xrealloc(void *, size_t);
void abac_split(char *string, char *delim, char **ret, int *num);

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...) do { } while (0)
#endif

#endif /* __UTIL_H__ */
