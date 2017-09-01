#!/usr/bin/perl

use strict;
use ABAC;
use Getopt::Long;
use Data::Dumper;
$Data::Dumper::Indent = 1;

my ($keystore, $role, $principal);
GetOptions(
    'keystore=s'    => \$keystore,
    'role=s'        => \$role,
    'principal=s'   => \$principal,
) || usage();

usage() unless defined $keystore && defined $role && defined $principal;

# code starts here

my $ctx = ABAC::Context->new;
$ctx->load_directory($keystore);

my ($success, $credentials) = $ctx->query($role, $principal);

if ($success) {
    print "Success\n";
}
else {
    print "Fail, here's a partial proof\n";
}

foreach my $credential (@$credentials) {
    printf "credential %s <- %s\n",
        $credential->head->string,
        $credential->tail->string;
}

sub usage {
    print "Usage: $0 \\\n";
    print "        --keystore <keystore> \\\n";
    print "        --role <role> --principal <principal>\n";
    print "    loads the keystore and runs the query role <-?- principal\n";
    exit 1;
}
