use Cro::Transform;
use Cro::LDAP::Request;
use Cro::LDAP::GenericParser;
use Cro::TCP;

class Cro::LDAP::RequestParser does Cro::Transform is Cro::LDAP::GenericParser {
    method consumes() { Cro::TCP::Message  }
    method produces() { Cro::LDAP::Request }
}
