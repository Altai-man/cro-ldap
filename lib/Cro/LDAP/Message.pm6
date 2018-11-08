use Cro::LDAP::ProtocolOp;

class Cro::LDAP::Message {
    subset MaxInt of Int where 0 < * < 2 ** 21 - 1;
    has MaxInt $.message-id;

    has Cro::LDAP::ProtocolOp $.protocol-op;
    has $.controls;
}
