package XMLRPC;

use strict;
use Carp;

use HTTP::Daemon::SSL;
use HTTP::Status qw(:constants);
use RPC::XML::Server;
use Net::SSLeay;

sub new {
    my ($class) = @_;

    my $srv = RPC::XML::Server->new(no_http => 1);
    return bless \$srv, $class;
}

sub add_method {
    my $self = shift;
    my $srv = $$self;
    $srv->add_method(@_);
}

sub verify {
    my ($ok, $store_ctx) = @_;

    my $x = Net::SSLeay::X509_STORE_CTX_get_current_cert($store_ctx);
    return $x ? 1 : 0;
}

sub run {
    my ($self, $port, $cert, $key) = @_;
    croak "Must supply a port to run on" unless defined $port;
    croak "Must give cert" unless defined $cert;
    croak "Must give key" unless defined $key;

    my $srv = $$self;

    my $daemon = HTTP::Daemon::SSL->new(
        LocalPort   => $port,
        ReuseAddr   => 1,
        SSL_key_file => $key,
        SSL_certy_file => $cert,
        SSL_verify_mode => 3,
        SSL_ca_path => 'FAIL',  # if this isn't here, verify never gets called :D
        SSL_verify_callback => \&verify,
    ) or die "Can't start HTTP daemon: $!";

    for ( ; ; ) {
        while (my $client = $daemon->accept) {
            my $pid = fork;
            next if $pid;

            my $peer_cert = $client->peer_certificate;
            $srv->{peer_cert} = $peer_cert;

            while (my $request = $client->get_request) {
                # require an SSL certificate
                if (!defined $srv->{peer_cert}) {
                    my $response = HTTP::Response->new(HTTP_UNAUTHORIZED);
                    $response->content("C'mon gimme a cert");
                    $client->send_response($response);
                    next;
                }

                # only handle POSTs to /RPC2
                if ($request->method ne 'POST' || $request->url->path ne '/RPC2') {
                    $client->send_error(HTTP_FORBIDDEN);
                    next;
                }

                my $response;

                eval {
                    my $rpc_response = $srv->dispatch($request->content);
                    my $content = $rpc_response->as_string;

                    $response = HTTP::Response->new(HTTP_OK);
                    $response->content($content);
                };

                # return an error on any kind of exception
                if ($@) {
                    $response = HTTP::Response->new(HTTP_BAD_REQUEST);
                    $response->content('Are you even trying?');
                }

                $client->send_response($response);
            }

            exit;
        }
    }
}

1;
