use Cro::TCP;
use Cro::Transform;
use Cro::LDAP::Types;
use Cro::LDAP::GenericParser;

class Cro::LDAP::RequestParser does Cro::Transform is Cro::LDAP::GenericParser {
    method consumes() { Cro::TCP::Message  }
    method produces() { Cro::LDAP::Message }
}
