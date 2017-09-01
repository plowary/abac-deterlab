
/* creddy.c */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <err.h>

#include "creddy_common.h"
#include "libabac_common.h"
#include "abac.h"
#include "abac_list.h"
#include "abac_verifier.h"

#define OPT_CN              1
#define OPT_VALIDITY        2
#define OPT_CERT            3
#define OPT_ISSUER          4
#define OPT_KEY             5
#define OPT_ROLE            6
#define OPT_SUBJECT_CERT    7
#define OPT_SUBJECT_ROLE    8
#define OPT_OUT             9 // the world oughta be opt-in only :(
#define OPT_ATTRCERT        10
#define OPT_SUBJECT_ID      11
#define OPT_SHOW            12
#define OPT_ATTRRULE        13

subject_t *subjects = NULL;
int num_subjects = 0;
int subjects_size = 0;

char **roles = NULL;
int num_roles = 0;
int roles_size = 0;

void subject(char *subject, int cert) {
    if (num_subjects == subjects_size) {
        subjects_size *= 2;
        subjects = xrealloc(subjects, sizeof(subject_t) * subjects_size);
    }

    int i = num_subjects++;
    subjects[i].id = NULL;
    subjects[i].cert = NULL;
    subjects[i].role = NULL;

    if (cert)
        subjects[i].cert = subject;
    else
        subjects[i].id = subject;
}

void role(char *role) {
    if (num_roles == roles_size) {
        roles_size *= 2;
        roles = xrealloc(roles, sizeof(char *) * roles_size);
    }

    int i = num_roles++;
    roles[i] = role;
}

int main(int argc, char **argv) {
    options_t options = { 0, };
    char *validity_str = NULL;

    libabac_init();

    subjects = xmalloc(sizeof(subject_t) * 2);
    subjects_size = 2;

    roles = xmalloc(sizeof(char *) * 2);
    roles_size = 2;

    struct option getopts[] = {
        { "help",       0, &options.help, 1 },
        { "generate",   0, &options.mode, MODE_GENERATE },
        { "verify",     0, &options.mode, MODE_VERIFY },
        { "keyid",      0, &options.mode, MODE_KEYID },
        { "attribute",  0, &options.mode, MODE_ATTRIBUTE },
        { "roles",      0, &options.mode, MODE_ROLES },
        { "version",    0, &options.mode, MODE_VERSION },
        { "display",    0, &options.mode, MODE_DISPLAY },

        { "cert",       1, 0, OPT_CERT },

        // generate options
        { "cn",         1, 0, OPT_CN },
        { "validity",   1, 0, OPT_VALIDITY },

        // attribute options
        { "issuer",     1, 0, OPT_ISSUER },
        { "key",        1, 0, OPT_KEY },
        { "role",       1, 0, OPT_ROLE },
        { "subject-cert", 1, 0, OPT_SUBJECT_CERT },
        { "subject-id", 1, 0, OPT_SUBJECT_ID },
        { "subject-role", 1, 0, OPT_SUBJECT_ROLE },
        { "out",          1, 0, OPT_OUT },

        // attribute_rule option
        { "attrrule",   1, 0, OPT_ATTRRULE },

        // verify option
        { "attrcert",   1, 0, OPT_ATTRCERT },

        // display options
        { "show",       1, 0, OPT_SHOW },

        { NULL },
    };

    for ( ; ; ) {
        int c = getopt_long(argc, argv, "", getopts, NULL);
        if (c < 0)
            break;

        switch (c) {
            // set the option from the value in the getopts struct
            case 0:
                continue;

            case OPT_CERT:
                options.cert = xstrdup(optarg);
                break;

            // generate options
            case OPT_CN:
                options.cn = xstrdup(optarg);
                break;
            case OPT_VALIDITY: // also an attribute option
                validity_str = xstrdup(optarg);
                break;

            // attribute options
            case OPT_ISSUER:
                options.issuer = xstrdup(optarg);
                break;
            case OPT_KEY: // also an generate option
                options.key = xstrdup(optarg);
                break;
            case OPT_ROLE:
                options.role = xstrdup(optarg);
                break;
            case OPT_SUBJECT_CERT:
                subject(xstrdup(optarg), 1);
                break;
            case OPT_SUBJECT_ID:
                subject(xstrdup(optarg), 0);
                break;
            case OPT_SUBJECT_ROLE:
                role(xstrdup(optarg));
                break;
            case OPT_OUT:
                options.out = xstrdup(optarg);
                break;

            // attribute rule options
            case OPT_ATTRRULE:
                options.attrrule = xstrdup(optarg);
                break;

            // verify options
            case OPT_ATTRCERT:
                options.attrcert = xstrdup(optarg);
                break;

            // display options
            case OPT_SHOW:
                options.show = xstrdup(optarg);
                break;

            case '?':
                break;

            default:
                printf("wat\n");
                return 45;
        }
    }

    if (options.help || optind < argc) {
        if (optind > 0 && optind < argc)
            printf("I don't understand %s\n", argv[optind]);
        usage(&options);
    }

    // parse the validity
    if (validity_str != NULL) {
        char suffix = 'd'; // default suffix is days
        int multiplier = 1;

        int len = strlen(validity_str);
        assert(len > 0);

        // get the suffix char if it's alphabetical
        if (isalpha(validity_str[len - 1])) {
            suffix = validity_str[len - 1];

            // truncate
            validity_str[len - 1] = '\0';
            --len;

            // make sure it's not only a suffix
            if (len == 0) {
                printf("Invalid validity\n");
                usage(&options);
            }
        }

        // convert the suffix to a multiplier
        switch(suffix) {
            case 's': multiplier =        1; break;
            case 'm': multiplier =       60; break;
            case 'h': multiplier =     3600; break;
            case 'd': multiplier =    86400; break;
            case 'y': multiplier = 31536000; break;
            default:
                printf("Invalid suffix, must be s m h d y\n");
                usage(&options);
        }

        // ascii to int
        char *end;
        options.validity = strtol(validity_str, &end, 10);
        if (errno != 0 || end - validity_str < len) {
            printf("Invalid validity\n");
            usage(&options);
        }

        if (options.validity <= 0) {
            printf("Invalid validity: must be > 0\n");
            usage(&options);
        }

        // multiply!
        options.validity *= multiplier;

        free(validity_str);
    }

    if (options.mode == MODE_ATTRIBUTE && options.attrrule == NULL) {
        int i;

        // have to do error checking on subjects here
        if (
                (num_subjects == 0) ||
                (num_subjects != num_roles && num_subjects != 1 && num_roles != 0)
           ) {
            printf(
                "You have %d subject%s and %d role%s, which is invalid\n",
                num_subjects, num_subjects == 1 ? "" : "s",
                num_roles, num_roles == 1 ? "" : "s"
            );
            usage(&options);
        }

        for (i = 0; i < num_roles; ++i)
            subjects[i].role = roles[i];
        free(roles);

        options.subjects = subjects;
        options.num_subjects = num_subjects;
    }

    // launch the sub command
    switch (options.mode) {
        case MODE_GENERATE:
            if (options.validity == 0) options.validity = 1080 * 86400;
            generate_main(&options);
            break;

        case MODE_KEYID:
            keyid_main(&options);
            break;

        case MODE_ATTRIBUTE:
            if (options.validity == 0) options.validity = 365 * 86400;
            if(options.attrrule)
                attribute_rule_main(&options);
                else attribute_main(&options);
            break;

        case MODE_ROLES:
            roles_main(&options);
            break;

        case MODE_VERIFY:
            verify_main(&options);
            break;

        case MODE_DISPLAY:
            display_main(&options);
            break;

        case MODE_VERSION:
            printf("ABAC/creddy " ABAC_VERSION "\n");
            break;

        default:
            usage(&options);
    }

    return 0;
}

void usage(options_t *opts) {
    if (opts->mode == MODE_GENERATE)
        printf(
            "Usage: creddy --generate --cn <name> [ --validity <time> ] [ --out <dir> ]\n"
            "    cert will be in ${name}_ID.der, private key in ${name}_private.pem\n"
            "    files output to dir if specified\n"
            "    default validity: 1080 days\n"
            "\n"
            "    time is specified with optional suffix: s m h d y\n"
            "    defaults to days if unspecified\n"
        );

    else if (opts->mode == MODE_VERIFY)
        printf(
            "Usage: creddy --verify --cert <cert> [ --attrcert <cert> ]\n"
            "    if attrcert is provided, verify that it was issued by cert\n"
        );

    else if (opts->mode == MODE_KEYID)
        printf(
            "Usage: creddy --keyid --cert <cert>\n"
        );

    else if (opts->mode == MODE_ATTRIBUTE)
        printf(
            "Usage: creddy --attribute \\\n"
            "                --issuer <cert> --key <key> --role <role> \\\n"
            "                [ --subject-cert <cert> | --subject-id <sha1> \\\n"
            "                    [ --subject-role <role> ]  ... ] \\\n"
            "                [ --validity <time> ] --out <file>\n"
            "    default validity: 365 days\n"
            "    provide exactly one of --subject-cert / --subject-id\n"
            "    give multiple --subject-{cert,id} / --subject-role pairs for intersection\n"
            "\n"
            "    time is specified with optional suffix: s m h d y\n"
            "    defaults to days if unspecified\n"
        );

    else if (opts->mode == MODE_ROLES)
        printf(
            "Usage: creddy --roles --cert <cert>\n"
        );

    else if (opts->mode == MODE_DISPLAY)
        printf(
            "Usage: creddy --display --show=[issuer,..,all] --cert <cert>\n"
            "   values for --show are comma-separated:\n"
            "       issuer      DN of issuer\n"
            "       subject     DN of subject\n"
            "       validity    validity period\n"
            "       roles       attribute cert roles (fails silently on ID certs)\n"
            "       all         all of the above\n"
            "   cert may be X.509 identity or attribute cert\n"
        );

    else
        printf(
            "Usage: creddy [ --<mode> ] [ --help ]\n"
            "    --generate:  generate X.509 identity cert and private key\n"
            "    --verify:    check validity of X.509 ID or XML attribute cert\n"
            "    --keyid:     get fingerprint from X.509 ID cert\n"
            "    --attribute: generate an XML attribute cert\n"
            "    --roles:     list roles from an XML attribute cert\n"
            "    --display:   list metadata from an X.509 identity or an XML attribute cert\n"
            "    --version:   display ABAC version\n"
        );


    exit(1);
}

void *xmalloc(size_t len) {
    void *ret = malloc(len);
    if (ret == NULL)
        err(1, "couldn't malloc %zu bytes\n", len);
    return ret;
}

void *xrealloc(void *ptr, size_t size) {
    void *ret = realloc(ptr, size);
    if (ret == NULL)
        err(1, "couldn't realloc %zu bytes\n", size);
    return ret;
}

char *xstrdup(char *string) {
    char *dup = strdup(string);
    if (dup == NULL)
        err(1, "Can't dup %s", string);
    return dup;
}

