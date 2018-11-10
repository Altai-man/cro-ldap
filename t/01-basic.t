use Cro::LDAP::Client;
use Cro::LDAP::Request;
use Cro::LDAP::Response;
use Test;

plan *;

my $promise = Promise.new;

class MockLDAP {
    method start() {
        start react {
            whenever IO::Socket::Async.listen('localhost', 20000) -> IO::Socket::Async $conn {
                whenever $conn.Supply(:bin) {
                    $conn.write(Buf.new(1, 2, 3));
                    $conn.close;
                }
            }
            CATCH {
                default {
                    say .^name, ': ', .Str;
                }
            }
        }
    }
}

MockLDAP.start;

my $client = Cro::LDAP::Client.new;

sleep 1;

await $client.connect('localhost', 20000);
# "Foo" name, simple authentication used
given $client.bind("Foo") -> $resp {
    ok $resp ~~ Cro::LDAP::Response::Bind, 'Got Response::Bind object';
}

await $promise;

done-testing;
