#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _options_t {
    char *keystore;
    char *role;
    char *principal;
    char *rulefile;
} options_t;

void get_options(int argc, char **argv, options_t *opts);
void free_options(options_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* __OPTIONS_H__ */
