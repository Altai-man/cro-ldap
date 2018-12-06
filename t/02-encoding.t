use Cro::LDAP::LDAPDN;
use Cro::LDAP::Authentication;
use Cro::LDAP::Message;
use Cro::LDAP::Request;
use Cro::LDAP::Response;
use ASN::Serializer;
use ASN::Parser;
use ASN::Types;
use Test;

my $parser = ASN::Parser.new(type => Cro::LDAP::Message);

# Controls

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp abandonRequest : 7,
#    controls {
#        { controlType '466F6F'H,
#          criticality TRUE },
#        { controlType '426172'H,
#          controlValue '4C6F737420496E2054696D65'H }
#    }
#}

my $request-with-controls-ber = Blob.new(
        0x30, 0x27, 0x02, 0x01, 0x05, 0x50, 0x01, 0x07, 0xA0, 0x1F, 0x30,
        0x08, 0x04, 0x03, 0x46, 0x6F, 0x6F, 0x01, 0x01, 0xFF, 0x30, 0x13,
        0x04, 0x03, 0x42, 0x61, 0x72, 0x04, 0x0C, 0x4C, 0x6F, 0x73, 0x74,
        0x20, 0x49, 0x6E, 0x20, 0x54, 0x69, 0x6D, 0x65);

my $request-with-controls = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((abandonRequest => Cro::LDAP::Request::Abandon.new(7))),
        controls => (Control.new(control-type => "466F6F", criticality => True),
                     Control.new(control-type => "426172", control-value => "4C6F737420496E2054696D65"))
        );

is-deeply ASN::Serializer.serialize($request-with-controls), $request-with-controls-ber, "Controls are serialized correctly";

is-deeply $parser.parse($request-with-controls-ber), $request-with-controls, "Controls are parsed correctly";

# Bind request

#value LDAPMessage ::= {
#    messageID 1,
#            protocolOp bindRequest : {
#        version 3,
#        name '64643D6578616D706C652C64633D636F6D'H,
#        authentication simple : '46466F'H
#    }
#}

my $bind-request-ber = Blob.new(
        0x30, 0x20, 0x02, 0x01, 0x01, 0x60, 0x1B, 0x02, 0x01, 0x03, 0x04,
        0x11, 0x64, 0x64, 0x3D, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x80, 0x03, 0x46, 0x6F,
        0x6F);

my $bind-request = Cro::LDAP::Message.new(
        message-id => 1,
        protocol-op => ProtocolChoice.new(('bindRequest' => Cro::LDAP::Request::Bind.new(
        version => 3,
                name =>"64643D6578616D706C652C64633D636F6D",
                authentication => AuthChoice.new((simple => ASN::Types::OctetString.new("466F6F"))))
                )));

is-deeply ASN::Serializer.serialize($bind-request, :mode(Implicit)), $bind-request-ber, "Bind request is serialized";

is-deeply $parser.parse($bind-request-ber), $bind-request, "Bind request is parsed";

# Bind response

#value LDAPMessage ::= {
#    messageID 2,
#    protocolOp bindResponse : {
#        resultCode success,
#        matchedDN ''H,
#        errorMessage ''H
#    }
#}

my $bind-response = Cro::LDAP::Message.new(
        message-id => 2,
        protocol-op => ProtocolChoice.new((bindResponse => Cro::LDAP::Response::Bind.new(
            result-code => success,
            matched-dn => "",
            error-message => "")
        )));

my $bind-response-ber = Blob.new(
        0x30, 0x0C, 0x02, 0x01, 0x02,0x61, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00);

is-deeply ASN::Serializer.serialize($bind-response, :mode(Implicit)) , $bind-response-ber, "Bind response is serialized";

is-deeply $parser.parse($bind-response-ber), $bind-response, "Bind response is parsed";

# Unbind request

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp unbindRequest : NULL
#}

my $unbind-request = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((unbindRequest => Cro::LDAP::Request::Unbind.new)));

my $unbind-request-ber = Blob.new(0x30, 0x05, 0x02, 0x01, 0x05, 0x42, 0x00);

is-deeply ASN::Serializer.serialize($unbind-request, :mode(Implicit)), $unbind-request-ber, "Unbind request is serialized";

is-deeply $parser.parse($unbind-request-ber), $unbind-request, "Unbind request is parsed";

# Search request

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp searchRequest : {
#        baseObject '64633D6578616D706C652C64633D636F6D'H,
#        scope wholeSubtree,
#        derefAliases neverDerefAliases,
#        sizeLimit 0,
#        timeLimit 0,
#        typesOnly FALSE,
#        filter equalityMatch : {
#            attributeDesc '6F626A656374436C617373'H,
#            assertionValue '6F7267616E697A6174696F6E616C506572736F6E'H
#        },
#        attributes { '646E'H, '636E'H }
#    }
#}

my $search-request = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((searchRequest => Cro::LDAP::Request::Search.new(
        base-object => "64633D6578616D706C652C64633D636F6D",
        scope => WholeSubtree,
        deref-aliases => NeverDerefAliases,
        size-limit => 0,
        time-limit => 0,
        types-only => False,
        filter => Filter.new((equalityMatch =>
                AttributeValueAssertion.new(
                        attribute-desc  => "6F626A656374436C617373",
                        assertion-value => "6F7267616E697A6174696F6E616C506572736F6E")
        )),
        attributes => ("646E", "636E")
                ))));

my $search-request-ber = Blob.new(
        0x30, 0x56, 0x02, 0x01, 0x05, 0x63, 0x51, 0x04, 0x11, 0x64, 0x63, 0x3D, 0x65, 0x78, 0x61,
        0x6D, 0x70, 0x6C, 0x65, 0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x0A, 0x01, 0x02, 0x0A,
        0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xA3, 0x23, 0x04, 0x0B,
        0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x43, 0x6C, 0x61, 0x73, 0x73, 0x04, 0x14, 0x6F, 0x72,
        0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x50, 0x65, 0x72,
        0x73, 0x6F, 0x6E, 0x30, 0x08, 0x04, 0x02, 0x64, 0x6E, 0x04, 0x02, 0x63, 0x6E);

is-deeply ASN::Serializer.serialize($search-request), $search-request-ber, "Search request is serialized";

is-deeply $parser.parse($search-request-ber), $search-request, "Search request is parsed";

# Abandon request

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp abandonRequest : 7
#}

my $abandon-request = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((abandonRequest => Cro::LDAP::Request::Abandon.new(7)))
        );

my $abandon-request-ber = Blob.new(0x30, 0x06, 0x02, 0x01, 0x05, 0x50, 0x01, 0x07);

is ASN::Serializer.serialize($abandon-request), $abandon-request-ber, "Abandon request is serialized";

is-deeply $parser.parse($abandon-request-ber), $abandon-request, "Abandon request is parsed";

done-testing;
