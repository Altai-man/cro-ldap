use Cro::Transform;
use Cro::LDAP::Response;
use Cro::TCP;

class Cro::LDAP::ResponseSerializer does Cro::Transform {
    method consumes() { Cro::LDAP::Response }
    method produces() { Cro::TCP::Message   }

    method transformer(Supply $responses) {
        supply {
            whenever $responses -> Cro::LDAP::Response $response {
                emit Cro::TCP::Message.new(data => $response.serialize);
            }
        }
    }
}
