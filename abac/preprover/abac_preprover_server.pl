#!/usr/bin/perl

use strict;
use Getopt::Long;
use Data::Dumper;
use IO::Socket::SSL;
use XMLRPC;

use lib '../swig/perl';
use ABAC;

use constant {
    PORT    => 8000,
};

my ($keystore, $cert, $key);
my $port = 8000;
GetOptions(
    'keystore=s'    => \$keystore,
    'port=i'        => \$port,
    'cert=s'        => \$cert,
    'key=s'        => \$key,
) || usage();

usage() unless defined $keystore && defined $cert && defined $key;

my $ctx = ABAC::Context->new;
$ctx->load_directory($keystore);

my $server = XMLRPC->new();
$server->add_method({
    name        => 'abac.query',
    code        => \&abac_query,
    signature   => [ 'struct struct' ],
});
$server->run($port, $cert, $key);

sub abac_query {
    my ($server, $request) = @_;

    my $peer_cert = $server->{peer_cert};
    my $peer_id = ABAC::SSL_keyid($peer_cert);

    # clone the context so the state remains pure between requests
    my $local_ctx = ABAC::Context->new($ctx);
    foreach my $cred (@{$request->{credentials}}) {
        my $ret = $local_ctx->load_id_chunk($cred->{issuer_cert});
        warn "Invalid issuer certificate" unless $ret == $ABAC::ABAC_CERT_SUCCESS;

        $ret = $local_ctx->load_attribute_chunk($cred->{attribute_cert});
        warn "Invalid attribute certificate" unless $ret == $ABAC::ABAC_CERT_SUCCESS;
    }

    my $role = $request->{role};
    print "$role <- $peer_id\n";
    my ($success, $credentials) = $local_ctx->query($role, $peer_id);

    return {
        success => $success,
        map {{
            attribute_cert  => RPC::XML::base64->new($_->attribute_cert),
            issuer_cert     => RPC::XML::base64->new($_->issuer_cert),
        }} @$credentials,
    };
}

sub usage {
    print "Usage: $0 \\\n";
    print "        --keystore <keystore> [ --port <port> ] \\\n";
    print "        --cert <cert.pem> --key <key.pem>\n";
    print "    port defaults to 8000\n";
    print "\n";
    print "    cert and key must be an OpenSSL cert and key\n";
    print "    ABAC cert and key will not work\n";
    exit 1;
}
