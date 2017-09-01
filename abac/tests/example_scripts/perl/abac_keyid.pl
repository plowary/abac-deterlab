#!/usr/bin/env perl

use ABAC;

my $filename = shift || die "Usage: abac_keyid.pl <cert.pem>\n";

my $id;
eval {
    # will throw a RuntimeException if it can't load the cert
    $id = ABAC::ID->new($filename);
};
if ($@) {
    print "ERROR, Problem loading cert: $@";
    exit;
}

print $id->keyid, "    OKAY\n";
