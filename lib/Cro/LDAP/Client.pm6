use ASN::Types;
use Cro;
use Cro::TCP;
use Cro::LDAP::Request;
use Cro::LDAP::RequestSerializer;
use Cro::LDAP::ResponseParser;
use Cro::LDAP::Authentication;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;
    has atomicint $!message-counter = -1;

    my class Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has $!next-response-vow;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out {
                    my $vow = $!next-response-vow;
                    $!next-response-vow = Nil;
                    $vow.keep($_.protocol-op.value);
                }
            }.tap;
        }

        method send-request(Cro::LDAP::Message $request) {
            my $next-response-promise = Promise.new;
            $!next-response-vow = $next-response-promise.vow;
            $!in.emit($request);
            $next-response-promise
        }
    }

    has Pipeline $!pipeline;

    method !get-pipeline(:$host, :$port) {
        my @parts;
        push @parts, Cro::LDAP::RequestSerializer;
        push @parts, Cro::TCP::Connector;
        push @parts, Cro::LDAP::ResponseParser;
        my $connector = Cro.compose(|@parts);
        my $in = Supplier::Preserving.new;
        my $out = $connector.establish($in.Supply, :$host, :$port);
        Pipeline.new(:$in, :$out);
    }

    method connect(Str $host, Int $port) {
        IO::Socket::Async.connect($host, $port).then(-> $promise {
            $!socket = $promise.result;
            $!pipeline = self!get-pipeline(:$host, :$port);
        });
    }

    method bind(Str $name, :$simple, :$sasl) {
        Promise(supply {
            my $message =Cro::LDAP::Request::Bind.new(
                    version => 3,
                    name => Cro::LDAP::LDAPDN.new("64643D6578616D706C652C64633D636F6D"),
                    authentication => simple => ASN::OctetString.new("466F6F"));
            whenever $!pipeline.send-request(self!wrap($message)) {
                emit $_;
            }
        });
    }

    my %request-types = 'Cro::LDAP::Request::Bind' => 'bindRequest';

    method !wrap($request) {
        my $message-id = $!message-counter ⚛+= 2;
        Cro::LDAP::Message.new(
                :$message-id,
                protocol-op => %request-types{$request.^name} => $request);
    }
}