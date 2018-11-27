use Cro::LDAP::Message;
use Cro::LDAP::Response;
use Cro::LDAP::Request;
use Cro::TCP;
use ASN::Parser::Async;

class Cro::LDAP::GenericParser {
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
