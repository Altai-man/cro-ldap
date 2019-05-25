use Cro::TCP;
use Cro::LDAP::Types;
use ASN::Parser::Async;

class Cro::LDAP::MessageParser does Cro::Transform {
    method consumes() { Cro::TCP::Message  }
    method produces() { Cro::LDAP::Message }

    method transformer(Supply $in) {
        supply {
            my $parser = ASN::Parser::Async.new(type => Cro::LDAP::Message);

            whenever $in -> Cro::TCP::Message $_ {
                $parser.process(.data);
            }

            whenever $parser.values {
                .emit;
            }
        }
    }
}
