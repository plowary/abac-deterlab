#!/usr/bin/perl

use strict;
use Getopt::Long;
use Data::Dumper;
use RPC::XML qw(smart_encode);
use RPC::XML::Parser;
use Crypt::SSLeay;
use LWP::UserAgent;
use HTTP::Request;

use ABAC;

use constant {
    USER_AGENT  => 'abac/0.2.0',
};

my ($keystore, $cert, $key, $role);
my $url = 'localhost:8000';
GetOptions(
    'keystore=s'    => \$keystore,
    'url=s'         => \$url,
    'cert=s'        => \$cert,
    'key=s'         => \$key,
    'role=s'        => \$role,
) || usage();

usage() unless defined $keystore && defined $cert && defined $key && defined $role;

# code starts here

# load the certificates
my $context = ABAC::Context->new;
$context->load_directory($keystore);

# build the XML RPC request
my $request = RPC::XML::request->new(
    'abac.query',
    smart_encode({
        role => $role,
        credentials => [
            map {{
                attribute_cert  => RPC::XML::base64->new($_->attribute_cert),
                issuer_cert     => RPC::XML::base64->new($_->issuer_cert),
            }} @{$context->credentials}
        ],
    }),
);

# encode and send the HTTP POST
my $request_body = $request->as_string;

$ENV{HTTPS_CERT_FILE} = $cert;
$ENV{HTTPS_KEY_FILE} = $key;
# $ENV{HTTPS_DEBUG} = 1;

my $ua = LWP::UserAgent->new;

my $request = HTTP::Request->new(
    'POST',
    "https://$url/RPC2",
);
$request->header('User-Agent', USER_AGENT);
$request->header('Content-Length', length $request_body);
$request->content($request_body);

my $response = $ua->request($request);
if (!$response->is_success) {
    die $response->status_line;
}

# decode the reply
my $xmlrpc_response = RPC::XML::Parser->new->parse($response->decoded_content);
my $result = $xmlrpc_response->value->value;

# load all the credentials from the reply
foreach my $cred (@{$result->{credentials}}) {
    $context->load_identity_chunk($cred->{attribute_cert});
    $context->load_attribute_chunk($cred->{attribute_cert});
}

my $success = $result->{success};
if ($success) {
    print "Success\n";
}

foreach my $cred (@{$context->credentials}) {
    printf "Credential %s <- %s\n",
        $cred->head->string,
        $cred->tail->string;
}

sub usage {
    print "Usage: $0 \\\n";
    print "        --keystore <keystore> [ --url <host:port> ] \\\n";
    print "        --cert <cert.pem> --key <key.pem> \\\n";
    print "        --role <keyid.role>\n";
    print "    url defaults to localhost:8000\n";
    exit 1;
}
