#!/usr/bin/perl

use strict;
use ABAC;
use Data::Dumper;
$Data::Dumper::Indent = 1;

use constant {
    ROLE        => '3f1aca4c5911b345d81c5f1a77675dce13249d0c.fed_create',
    PRINCIPAL   => '5839d714b16bbe108642c5eb586c2173420bed19',
};

my $keystore = shift || die "Usage: prover.pl <keystore> [-v]\n";
my $verbose = shift;

my $ctx = ABAC::Context->new;
$ctx->load_directory("$keystore/1");

my $ctx_add = ABAC::Context->new($ctx);

my ($success, $credentials) = $ctx_add->query(ROLE, PRINCIPAL);
my $result = $success ? 'FAIL' : 'PASS';
printf "%-60s %s\n", 'Unsuccessful query:', $result;
dump_creds($credentials) if $verbose;

$ctx_add->load_directory("$keystore/2");
my ($success, $credentials) = $ctx_add->query(ROLE, PRINCIPAL);
my $result = $success ? 'PASS' : 'FAIL';
printf "%-60s %s\n", 'Added credentials, successful query:', $result;
dump_creds($credentials) if $verbose;

my ($success, $credentials) = $ctx->query(ROLE, PRINCIPAL);
my $result = $success ? 'FAIL' : 'PASS';
printf "%-60s %s\n", 'Original context, failed query:', $result;
dump_creds($credentials) if $verbose;

sub dump_creds {
    my $credentials = shift;
    foreach my $credential (@$credentials) {
        printf "%s <- %s\n",
            $credential->head->string,
            $credential->tail->string;
    }
}
