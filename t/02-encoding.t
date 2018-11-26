use Cro::LDAP::LDAPDN;
use Cro::LDAP::Authentication;
use Cro::LDAP::Request;
use ASN::Types;
use Test;

my $bind-request-ber = Blob.new(
        0x30, 0x22, 0x02, 0x01, 0x01, 0x60, 0x1B, 0x02, 0x01, 0x03, 0x04,
        0x11, 0x64, 0x64, 0x3D, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x80, 0x03, 0x46, 0x6F,
        0x6F, 0xA0, 0x00);

my $bind-request = Cro::LDAP::Request.new(
        message-id => 1,
        protocol-op => bindRequest => Cro::LDAP::Request::Bind.new(
                version => 3,
                name => Cro::LDAP::LDAPDN.new("64643D6578616D706C652C64633D636F6D"),
                authentication => simple => ASN::OctetString.new("466F6F"))
        );

is-deeply $bind-request.serialize, $bind-request-ber, "Bind request is serialized";

# On implicit tagging
# * If inside of CHOICE and implicit tag is defined, use it with context-specific bit.
# * If inside CHOICE and APPLICATION-wide tag defined, use it with application bit.
# * Use type tag

# ASN1STEP: Encoding of value notation  for PDU #1:
# Encoding to the file 'data.ber' using BER encoding rule...
# LDAPMessage SEQUENCE: tag = [UNIVERSAL 16] constructed; length = 34
#  messageID MessageID INTEGER: tag = [UNIVERSAL 2] primitive; length = 1
#    1
#  protocolOp CHOICE
#    bindRequest BindRequest SEQUENCE: tag = [APPLICATION 0] constructed; length = 27
#      version INTEGER: tag = [UNIVERSAL 2] primitive; length = 1
#        3
#      name LDAPDN OCTET STRING: tag = [UNIVERSAL 4] primitive; length = 17
#        0x64643d6578616d706c652c64633d636f6d
#      authentication AuthenticationChoice CHOICE
#        simple OCTET STRING: tag = [0] primitive; length = 3
#          0x466f6f
#  controls Controls SEQUENCE OF: tag = [0] constructed; length = 0
#Encoded successfully in 36 bytes:
# (30 22 - SEQUENCE
#     (02 01 01) - INTEGER, len 1, value 1
#     (60 1B - APPLICATION 0, inside of CHOICE without numeration, 0b01100000 (APPLICATION AND complex)
#        (02 01 03) <- INTEGER, version
#        (04 11 64 64 3D 65 78 61 6D 70 6C 65 2C 64 63 3D 63 6F 6D) <- OCTET STRING, name
#        (80 03 46 6F 6F) <- inside of CHOICE, with numeration, context-specific, 0b10000000
#     (A0 00) <- SEQUENCE of controls, empty, context-specific, complex, 0b10100000

done-testing;
