use Cro::LDAP::LDAPDN;
use Cro::LDAP::Authentication;
use Cro::LDAP::Message;
use ASN::Types;
use Test;

# Bind request

my $bind-request-ber = Blob.new(
        0x30, 0x22, 0x02, 0x01, 0x01, 0x60, 0x1B, 0x02, 0x01, 0x03, 0x04,
        0x11, 0x64, 0x64, 0x3D, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x80, 0x03, 0x46, 0x6F,
        0x6F, 0xA0, 0x00);

my $bind-request = Cro::LDAP::Message.new(
        message-id => 1,
        protocol-op => bindRequest => Cro::LDAP::Request::Bind.new(
                version => 3,
                name => Cro::LDAP::LDAPDN.new("64643D6578616D706C652C64633D636F6D"),
                authentication => simple => ASN::OctetString.new("466F6F"))
        );

is-deeply $bind-request.serialize, $bind-request-ber, "Bind request is serialized";

is-deeply Cro::LDAP::Message.parse($bind-request-ber), $bind-request, "Bind request is parsed";

# Bind response

#value LDAPMessage ::= {
#    messageID 2,
#    protocolOp bindResponse : {
#        resultCode success,
#        matchedDN ''H,
#        errorMessage ''H
#    }
#}

# 30 0C 02 01 02 61 07 0A 01 00 04 00 04 00



done-testing;
