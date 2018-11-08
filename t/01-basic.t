use Test;
use Cro::LDAP::Client;

class MockLDAP {
    method start() {
        start react {
            whenever IO::Socket::Async.listen('0.0.0.0', 3434) -> IO::Handle $conn {
                whenever $conn.Supply.lines -> $line {
                    $conn.write(Buf.new(1, 1, 1));
                    $conn.close;
                    my $done = True;
                    done;
                    Promise.in(5).then: {
                        unless $done {
                            die 'Foo!';
                        }

                    }
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

$client.connect('0.0.0.0', 3434);
# "Foo" name, simple authentication used
given $client.bind("Foo") -> $resp {
    say $resp;
}

done-testing;
