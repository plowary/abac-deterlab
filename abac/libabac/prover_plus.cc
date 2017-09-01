#include <err.h>
#include <stdio.h>
#include <vector>

#include <abac.hh>

#include "options.h"

using namespace ABAC;
using std::vector;

int main(int argc, char **argv) {
    int i;
    abac_credential_t *cred;

    options_t opts = { 0, };
    get_options(argc, argv, &opts);

    Context ctx;
    ctx.load_directory(opts.keystore);

    bool success;
    vector<Credential> credentials = ctx.query(
        opts.role, opts.principal,
        success
    );

    if (success)
        puts("success");
    for (vector<Credential>::iterator i = credentials.begin(); i != credentials.end(); ++i) {
        printf("credential %s <- %s\n",
            i->head().string(),
            i->tail().string()
        );
    }

    return 0;
}
