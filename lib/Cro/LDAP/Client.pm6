use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::RequestSerializer;
use Cro::LDAP::ResponseParser;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;
    has atomicint $!message-counter = 1;

    my class Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has $!next-response-vow;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out {
                    my $vow = $!next-response-vow;
                    $!next-response-vow = Nil;
                    $vow.keep($_.protocol-op.ASN-value.value);
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

    method bind(Str $name, :$auth) {
        Promise(supply {
            my $authentication;
            with $auth {
                $authentication = AuthenticationChoice.new($auth ~~ Str ??
                        simple => ASN::Types::OctetString.new($auth) !!
                        sasl => SaslCredentials.new(|$auth));
            } else {
                $authentication = AuthenticationChoice.new((simple => ASN::Types::OctetString.new("")));
            }
            my $message = BindRequest.new(
                    version => 3,:$name,
                    :$authentication);
            whenever $!pipeline.send-request(self!wrap($message)) {
                emit $_;
            }
        });
    }

    my %request-types = 'BindRequest' => 'bindRequest';

    method !wrap($request) {
        my $message-id = $!message-counter⚛++;
        Cro::LDAP::Message.new(
                :$message-id,
                protocol-op => ProtocolOp.new((%request-types{$request.^name} => $request)));
    }
}