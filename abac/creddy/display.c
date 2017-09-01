
/* display.c */

#include <time.h>
#include <string.h>
#include <err.h>

#include "libabac_common.h"
#include "creddy_common.h"
#include "abac.h"
#include "abac_verifier.h"

// helper
void _print_validity(struct tm not_before, struct tm not_after);
void _print_info(abac_attribute_t *attr, int show_issuer, int show_subject, int show_validity, int show_roles, char*);

void display_main(options_t *opts) {
    if (opts->cert == NULL)
        usage(opts);

    char *show = opts->show;
    if (show == NULL)
        usage(opts);

    int show_issuer = 0;
    int show_subject = 0;
    int show_validity = 0;
    int show_roles = 0;
    char *opt;

    while ((opt = strsep(&show, ",")) != NULL) {
        if (strcmp(opt, "issuer") == 0)
            show_issuer = 1;
        else if (strcmp(opt, "subject") == 0)
            show_subject = 1;
        else if (strcmp(opt, "validity") == 0)
            show_validity = 1;
        else if (strcmp(opt, "roles") == 0)
            show_roles = 1;
        else if (strcmp(opt, "all") == 0) {
            show_issuer = 1;
            show_subject = 1;
            show_validity = 1;
            show_roles = 1;
        }
        else {
            printf("Error: Unknown option to --show: %s\n", opt);
            usage(opts);
        }
    }

    // first try ID cert
    abac_id_t *id = abac_id_from_file(opts->cert);
    if (id != NULL) {
        if (show_issuer) {
            char *issuer = abac_id_issuer(id);
            printf("Issuer: %s\n", issuer);
            free(issuer);
        }

        if (show_subject) {
            char *subject = abac_id_subject(id);
            printf("Subject: %s\n", subject);
            free(subject);
        }

        if (show_validity) {
            struct tm not_before, not_after;
            abac_id_validity(id, &not_before, &not_after);
            _print_validity(not_before, not_after);
        }

        abac_id_free(id);
        return;
    }

    // then try attribute cert
    abac_attribute_t *attr;
    abac_list_t *dummy_cert_list=abac_list_new();
    abac_list_t *attr_list = abac_attribute_certs_from_file(dummy_cert_list,opts->cert);
    int sz=abac_list_size(attr_list);
    abac_list_foreach(attr_list, attr,
        _print_info(attr,show_issuer,show_subject,show_validity,show_roles, opts->cert);
        abac_attribute_free(attr);
    );
    abac_list_free(attr_list);
    abac_id_cert_t *cert;
    abac_list_foreach(dummy_cert_list, cert,
        abac_id_cert_free(cert);
    );
    abac_list_free(dummy_cert_list);

    // give up if neither works
    if(sz==0)
        errx(1, "Couldn't load %s as an ID or attribute", opts->cert);
}

void _print_info(abac_attribute_t *attr, int show_issuer, int show_subject, int show_validity, int show_roles, char *fname)
{
    if (attr != NULL) {
        abac_id_t *issuer_id=abac_attribute_issuer_id(attr);
        if (show_issuer && issuer_id) {
            char *issuer = abac_id_issuer(issuer_id);
            printf("Issuer: %s\n", issuer);
            free(issuer);
        }
        if (show_subject && issuer_id) {
            char *subject = abac_id_subject(issuer_id);
            printf("Subject: %s\n", subject);
            free(subject);
        }
        if (show_validity) {
            struct tm not_before, not_after;
            abac_attribute_validity(attr, &not_before, &not_after);
            _print_validity(not_before, not_after);
        }
        if (show_roles) {
            char *role_string = abac_attribute_role_string(attr);
            if (role_string == NULL) errx(1, "Couldn't get attributes from %s", fname );
            printf("Roles: %s\n", role_string);
            free(role_string);
        }
    }
}

// display the validity period of a cert
void _print_validity(struct tm not_before, struct tm not_after) {
    char buf[256];
    printf("Validity:\n");

    strftime(buf, sizeof(buf), "%F %T %Z", &not_before);
    printf("    Not before: %s [%lld]\n", buf, (long long) mktime(&not_before));

    strftime(buf, sizeof(buf), "%F %T %Z", &not_after);
    printf("    Not after:  %s [%lld]\n", buf, (long long) mktime(&not_after));
}
