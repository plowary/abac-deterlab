#!/usr/bin/perl

use ABAC;

my $filename = shift || die "Usage: creddy_keyid.pl <cert.pem>\n";

my $id;
eval {
    # will throw a RuntimeException if it can't load the cert
    $id = Creddy::ID->new($filename);
};
if ($@) {
    print "Problem loading cert: $@";
    exit;
}

print $id->keyid, "\n";
