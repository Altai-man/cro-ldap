use Cro::LDAP::ProtocolOp;

role Cro::LDAP::Response does Cro::LDAP::ProtocolOp {
    method deserialize(Blob $data --> Cro::LDAP::Response) {...}
    method serialize(--> Blob) {...}
}

class Cro::LDAP::Response::Bind does Cro::LDAP::Response {
    method serialize(--> Blob) {}
    method deserialize(Blob $data --> Cro::LDAP::Response) {}
}
