#ifndef __CREDDY_COMMON_H__
#define __CREDDY_COMMON_H__

/* used locally by creddy */

#include <stdlib.h>


typedef struct _subject_t {
    char *cert;
    char *id;
    char *role;
} subject_t;

typedef struct _options_t {
    int help;
    int mode;

    char *cert;

    // generate options
    char *cn;
    int validity;

    // attribute options
    char *issuer;
    char *key;
    char *role;
    subject_t *subjects;
    int num_subjects;
    char *out;

    // verify options
    char *attrcert;

    // attribute_rule options
    char *attrrule;

    // display options
    char *show;
} options_t;

#define MODE_GENERATE   1
#define MODE_VERIFY     2
#define MODE_KEYID      3
#define MODE_ATTRIBUTE  4
#define MODE_ROLES      5
#define MODE_VERSION    6
#define MODE_DISPLAY    7

void usage(options_t *opts);
void *xmalloc(size_t len);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(char *string);

// sub programs
void generate_main(options_t *opts);
void keyid_main(options_t *opts);
void attribute_main(options_t *opts);
void attribute_rule_main(options_t *opts);
void roles_main(options_t *opts);
void verify_main(options_t *opts);
void display_main(options_t *opts);

#endif /* __CREDDY_COMMON_H__ */
