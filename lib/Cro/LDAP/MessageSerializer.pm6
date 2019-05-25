use ASN::Serializer;
use Cro::TCP;
use Cro::Transform;
use Cro::LDAP::Types;

class Cro::LDAP::MessageSerializer does Cro::Transform {
    method consumes() { Cro::LDAP::Message }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $messages) {
        my $serializer = ASN::Serializer.new;
        supply {
            whenever $messages -> $msg {
                emit Cro::TCP::Message.new(data => $serializer.serialize($msg));
            }
        }
    }
}
