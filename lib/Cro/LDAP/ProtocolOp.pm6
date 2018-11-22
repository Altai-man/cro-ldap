use Cro::Message;

# Marker role for all operations
role Cro::LDAP::ProtocolOp does Cro::Message {
    has Int $.message-id is required;
}
