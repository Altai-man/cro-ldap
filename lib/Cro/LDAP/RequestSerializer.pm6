use Cro::TCP;
use Cro::LDAP::Message;
use Cro::Transform;
use ASN::Serializer;

class Cro::LDAP::RequestSerializer does Cro::Transform {
    method consumes() { Cro::LDAP::Message }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $request-stream) {
        my $serializer = ASN::Serializer.new;
        supply {
            whenever $request-stream -> $request {
                emit Cro::TCP::Message.new(data => $serializer.serialize($request));
            }
        }
    }
}
