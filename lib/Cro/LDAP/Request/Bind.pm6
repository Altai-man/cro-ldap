use Cro::LDAP::Authentication;
use Cro::LDAP::ProtocolOp;
use Cro::LDAP::LDAPDN;

class Cro::LDAP::Rquest::Bind does Cro::LDAP::ProtocolOp {
    subset Version of Int where 0 < * < 128;
    has Version $.version;

    has Cro::LDAP::LDAPDN $.name;
    has Cro::LDAP::Authentication $.authentication;
}
