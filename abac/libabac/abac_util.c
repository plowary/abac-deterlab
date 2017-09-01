
/* abac_util.c */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include <abac_util.h>

/**
 * Malloc, fatal on error.
 */
void *abac_xmalloc(size_t size) {
    void *ret;
    
    ret = malloc(size);
    if (ret == NULL)
        err(1, "malloc");

    return ret;
}

void abac_chunk_free(abac_chunk_t *chunk)
{
   if(chunk->len)
       free(chunk->ptr);
   chunk->len=0;
   chunk->ptr=NULL;
}

int abac_chunk_null(abac_chunk_t *chunk)
{
    if(chunk->ptr==NULL) return 1;
    return 0;
}

int abac_chunk_show(abac_chunk_t *chunk)
{
    if(chunk->ptr==NULL) {
        fprintf(stderr,"abac_chunk_show: chunk is NULL\n");
	return 1;
    }
    fprintf(stderr,"abac_chunk_show: chunk is not NULL (%ld)\n",(long)chunk->ptr);
    return 0;
}

/**
 * strdup fatal on error
 */
char *abac_xstrdup(char *source) {
    char *ret;

    if (source == NULL)
        return NULL;

    ret = strdup(source);
    if (ret == NULL)
        err(1, "strdup");

    return ret;
}

void *abac_xrealloc(void *ptr, size_t size) {
    void *ret = realloc(ptr, size);
    if (ret == NULL)
        err(1, "couldn't realloc %zu bytes\n", size);
    return ret;
}

/**
 * Split a string based on the given delimiter.  The substrings are pointers
 * into string, which has string terminators added to slice it into substrings.
 * Do not free the returned substrings.  num passes in the maximum number of
 * substrings to create and is returned as the number actually created.
 */
#define MAXSPLIT    1024
void abac_split(char *string, char *delim, char **ret, int *num) {
    int len = strlen(delim);
    char *start = string;
    int count = 0;
    int lim = (num && *num > 0) ? *num : MAXSPLIT;

    // split the string by the delim.  Split into at most lim parts
    while ((start = strstr(string, delim)) != NULL && count < lim-1) {
        *start = 0;
        ret[count++] = string;
        string = start + len;
    }
    ret[count++] = string;

    *num = count;
}

int abac_clean_name(char *string) {
    int i;

    assert(string != NULL);

    // must start with a letter/number
    if (!isalnum(string[0])) return 0;

    // Name must be alphanumeric or - or _ or :
    for (i = 1; string[i] != '\0'; ++i)
        if (!isalnum(string[i]) && string[i] != '-' && string[i] != '_' &&
                string[i] != ':')
            return 0;

    return 1;
}

