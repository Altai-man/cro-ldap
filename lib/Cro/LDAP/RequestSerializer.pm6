use Cro::TCP;
use Cro::LDAP::Request;
use Cro::Transform;

class Cro::LDAP::RequestSerializer does Cro::Transform {
    method consumes() { Cro::LDAP::Request }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $request-stream) {
        supply {
            whenever $request-stream -> Cro::LDAP::Request $request {
                emit Cro::TCP::Message.new(data => $request.serialize);
            }
        }
    }
}
