use Cro::Transform;
use Cro::TCP;
use Cro::LDAP::Message;
use Cro::LDAP::GenericParser;

class Cro::LDAP::ResponseParser does Cro::Transform is Cro::LDAP::GenericParser {
    method consumes() { Cro::TCP::Message   }
    method produces() { Cro::LDAP::Message  }
}
