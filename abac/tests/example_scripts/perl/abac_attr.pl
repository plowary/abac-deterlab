#!/usr/bin/env perl

use strict;
use ABAC;
use Getopt::Long;
use Data::Dumper;
$Data::Dumper::Indent = 1;

my ($idfile, $keyfile, $id2file, $attrxml);
GetOptions(
    'id=s'      => \$idfile,
    'key=s'     => \$keyfile,
    'id2=s'     => \$id2file,
    'attr=s'    => \$attrxml,
) || usage();

usage() unless defined $idfile && defined $keyfile && $id2file && defined $attrxml;

my $ctx = ABAC::Context->new;

my $ice;
my $choco;
eval {
    # will throw a RuntimeException if it can't load the cert
    $ice = ABAC::ID->new($idfile);
    $ice->load_privkey($keyfile);
    $choco = ABAC::ID->new($id2file);
};
if ($@) {
    print "ERROR, Problem loading cert: $@";
    exit;
}
print $ice->keyid, "   , ice cream\n";
print $choco->keyid, "   , chocolate\n";

my $attr;
eval {
    $attr = ABAC::Attribute->new($ice,"delicious",0);
    $attr->principal($choco->keyid());
    $attr->bake();
};

if ($@) {
    print "ERROR, Problem baking attribute: $@";
    exit;
}

eval {
    $attr->write_file($attrxml);
};
if ($@) {
    print "ERROR, Problem writing attribute's xml file: $@";
    exit;
}

sub usage {
    print "Usage: $0 \\\n";
    print "        --id <idfile> --key <keyfile> \n";
    print "        --id2 <id2file> --attr <attrxml>\n";
    print "    loads id/key, id2, and makes attr\n";
    exit 1;
}

