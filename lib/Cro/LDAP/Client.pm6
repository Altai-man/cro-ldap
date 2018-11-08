use Cro;
use Cro::TCP;
use Cro::LDAP::Request;
use Cro::LDAP::RequestSerializer;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;
    has $!pipeline;

    my class Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has Promise $!next-response-vow;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out {
                    my $vow = $!next-response-vow;
                    $!next-response-vow = Nil;
                    $vow.keep($_);
                }
            }
        }

        method send-request($request --> Promise) {
            my $next-response-promise = Promise.new;
            $!next-response-vow = $next-response-promise.vow;
            $!in.emit($request);
            $next-response-promise
        }
    }

    method !get-pipeline($host, $port) {
        my @parts;
        push @parts, Cro::LDAP::RequestSerializer;
        push @parts, Cro::TCP::Connector;
        push @parts, Cro::LDAP::ResponseParser;
        my $connector = Cro.compose(|@parts);
        my $in = Supplier::Preserving.new;
        my $out = $connector.establish($in.Supply, :$host, :$port);
        Pipeline.new(:$in);
    }

    method connect(Str $host, Int $port) {
        IO::Socket::Async.connect($host, $port).then(-> $promise {
            await $promise;
            $!socket = $promise;

            $!pipeline = self!get-pipeline(:$host, :$port);

            say "Promise is done!";
            CATCH {
                default {
                    say "Promise is broken!";
                }
            }
        });
    }

    method bind(Str $name, :$simple, :$sasl) {
        Cro::LDAP::Rquest::Bind.new;
    }
}