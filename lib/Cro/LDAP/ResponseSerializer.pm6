use ASN::Serializer;
use Cro::TCP;
use Cro::Transform;
use Cro::LDAP::Types;

class Cro::LDAP::ResponseSerializer does Cro::Transform {
    method consumes() { Cro::LDAP::Message }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $responses) {
        my $serializer = ASN::Serializer.new;
        supply {
            whenever $responses -> $response {
                emit Cro::TCP::Message.new(data => $serializer.serialize($response));
            }
        }
    }
}
