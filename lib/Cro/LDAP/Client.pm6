use Cro;
use Cro::TCP;
use Cro::LDAP::Request;
use Cro::LDAP::RequestSerializer;
use Cro::LDAP::ResponseParser;
use Cro::LDAP::Authentication;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;

    my class Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has $!next-response-vow;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out {
                    my $vow = $!next-response-vow;
                    $!next-response-vow = Nil;
                    $vow.keep($_);
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

            CATCH {
                default {
                    .note;
                    say "Promise is broken!";
                }
            }
        });
    }

    method bind(Str $name, :$simple, :$sasl) {
        Promise(supply {
            my $bind-req = do Cro::LDAP::Request::Bind.new(
                    message-id => 1,
                    version => 3,
                    name => $name,
                    authentication => Simple);
            whenever $!pipeline.send-request($bind-req) {
                emit $_;
            }
        });
    }
}