use Cro::LDAP::Authentication;
use Cro::LDAP::ProtocolOp;
use Cro::LDAP::LDAPDN;

role Cro::LDAP::Request does Cro::LDAP::ProtocolOp {
    method serialize(--> Blob) {...}
    method deserialize(Blob $data --> Cro::LDAP::Request) {...}
}

class Cro::LDAP::Request::Bind does Cro::LDAP::Request {
    subset Version of Int where 0 < * < 128;
    has Version $.version;

    has Cro::LDAP::LDAPDN $.name;
    has Cro::LDAP::Authentication $.authentication;
    method serialize(--> Blob) {
        Blob.new(1, 2, 3);
    }
    method deserialize(Blob $data --> Cro::LDAP::Request) {
        Cro::LDAP::Request.new;
    }
}
