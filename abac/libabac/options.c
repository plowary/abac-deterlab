
/* options.c */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"

static void _usage(char *name) {
    printf(
        "Usage: %s \\\n"
        "        --keystore <keystore> \\\n"
        "        --role <keyid.role> --principal <keyid>\n"
        "        --dump <file>\n"
        "    loads the keystore and runs the query role <-?- principal\n",
        name
    );
    exit(1);
}

void free_options(options_t *opts)
{
    if(opts->keystore) free(opts->keystore); 
    if(opts->role) free(opts->role);
    if(opts->principal) free(opts->principal);
    if(opts->rulefile) free(opts->rulefile);
}

void get_options(int argc, char **argv, options_t *opts) {
#define OPT_KEYSTORE    1
#define OPT_ROLE        2
#define OPT_PRINCIPAL   3
#define OPT_DUMP        4
    struct option options[] = {
        { "keystore",   1, 0, OPT_KEYSTORE  },
        { "role",       1, 0, OPT_ROLE      },
        { "principal",  1, 0, OPT_PRINCIPAL },
        { "dump",       1, 0, OPT_DUMP },
        { 0 },
    };

    for ( ; ; ) {
        int c = getopt_long(argc, argv, "", options, NULL);
        if (c < 0)
            break;

        switch (c) {
            case OPT_KEYSTORE:
                opts->keystore = strdup(optarg);
                break;
            case OPT_ROLE:
                opts->role = strdup(optarg);
                break;
            case OPT_PRINCIPAL:
                opts->principal = strdup(optarg);
                break;
            case OPT_DUMP:
                opts->rulefile = strdup(optarg);
                break;


            default:
                _usage(argv[0]);
        }
    }

    if (!(opts->keystore && opts->role && opts->principal) && !(opts->rulefile) )
        _usage(argv[0]);
}
