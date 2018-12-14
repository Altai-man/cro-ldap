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

my $request-with-controls-ber = Buf.new(
        0x30, 0x27, 0x02, 0x01, 0x05, 0x50, 0x01, 0x07, 0xA0, 0x1F, 0x30,
        0x08, 0x04, 0x03, 0x46, 0x6F, 0x6F, 0x01, 0x01, 0xFF, 0x30, 0x13,
        0x04, 0x03, 0x42, 0x61, 0x72, 0x04, 0x0C, 0x4C, 0x6F, 0x73, 0x74,
        0x20, 0x49, 0x6E, 0x20, 0x54, 0x69, 0x6D, 0x65);

my $request-with-controls = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((abandonRequest => Cro::LDAP::Request::Abandon.new(7))),
        controls => (Control.new(control-type => "Foo", criticality => True),
                Control.new(control-type => "Bar", control-value => "Lost In Time"))
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

my $bind-request-ber = Buf.new(
        0x30, 0x20, 0x02, 0x01, 0x01, 0x60, 0x1B, 0x02, 0x01, 0x03, 0x04,
        0x11, 0x64, 0x64, 0x3D, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x80, 0x03, 0x46, 0x6F,
        0x6F);

my $bind-request = Cro::LDAP::Message.new(
        message-id => 1,
        protocol-op => ProtocolChoice.new(('bindRequest' => Cro::LDAP::Request::Bind.new(
                version => 3,
                name =>"dd=example,dc=com",
                authentication => AuthChoice.new((simple => ASN::Types::OctetString.new("Foo"))))
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

my $bind-response-ber = Buf.new(
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

my $unbind-request-ber = Buf.new(0x30, 0x05, 0x02, 0x01, 0x05, 0x42, 0x00);

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
                base-object => "dc=example,dc=com",
                scope => WholeSubtree,
                deref-aliases => NeverDerefAliases,
                size-limit => 0,
                time-limit => 0,
                types-only => False,
                filter => Filter.new((equalityMatch =>
                        AttributeValueAssertion.new(
                                attribute-desc  => "objectClass",
                                assertion-value => "organizationalPerson")
                )),
                attributes => ("dn", "cn")
                ))));

my $search-request-ber = Buf.new(
        0x30, 0x56, 0x02, 0x01, 0x05, 0x63, 0x51, 0x04, 0x11, 0x64, 0x63, 0x3D, 0x65, 0x78, 0x61,
        0x6D, 0x70, 0x6C, 0x65, 0x2C, 0x64, 0x63, 0x3D, 0x63, 0x6F, 0x6D, 0x0A, 0x01, 0x02, 0x0A,
        0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xA3, 0x23, 0x04, 0x0B,
        0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x43, 0x6C, 0x61, 0x73, 0x73, 0x04, 0x14, 0x6F, 0x72,
        0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x50, 0x65, 0x72,
        0x73, 0x6F, 0x6E, 0x30, 0x08, 0x04, 0x02, 0x64, 0x6E, 0x04, 0x02, 0x63, 0x6E);

is-deeply ASN::Serializer.serialize($search-request), $search-request-ber, "Search request is serialized";

is-deeply $parser.parse($search-request-ber), $search-request, "Search request is parsed";

# Search result

#value LDAPMessage ::= {
#    messageID 50,
#    protocolOp searchResEntry : {
#        objectName '74657374444E'H,
#        attributes {
#            {
#                type '6669727374'H,
#                vals { '457073696C6F6E'H, '536F6C7574696F6E'H } },
#            {
#                type '7365636F6E64'H,
#                vals { '47616D6D61'H, '4E6172626572616C'H }
#            }
#        }
#    }
#}

my $search-result-entry-ber1 = Buf.new(
        0x30, 0x4A, 0x02, 0x01, 0x32, 0x64, 0x45, 0x04, 0x06, 0x74, 0x65, 0x73,
        0x74, 0x44, 0x4E, 0x30, 0x3B, 0x30, 0x1C, 0x04, 0x05, 0x66, 0x69, 0x72,
        0x73, 0x74, 0x31, 0x13, 0x04, 0x07, 0x45, 0x70, 0x73, 0x69, 0x6C, 0x6F,
        0x6E, 0x04, 0x08, 0x53, 0x6F, 0x6C, 0x75, 0x74, 0x69, 0x6F, 0x6E, 0x30,
        0x1B, 0x04, 0x06, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x31, 0x11, 0x04,
        0x05, 0x47, 0x61, 0x6D, 0x6D, 0x61, 0x04, 0x08, 0x4E, 0x61, 0x72, 0x62,
        0x65, 0x72, 0x61, 0x6C);

my $search-result-entry-ber2 = Buf.new(
        0x30, 0x4A, 0x02, 0x01, 0x32, 0x64, 0x45, 0x04, 0x06, 0x74, 0x65, 0x73,
        0x74, 0x44, 0x4E, 0x30, 0x3B, 0x30, 0x1C, 0x04, 0x05, 0x66, 0x69, 0x72,
        0x73, 0x74, 0x31, 0x13, 0x04, 0x07, 0x45, 0x70, 0x73, 0x69, 0x6C, 0x6F,
        0x6E, 0x04, 0x08, 0x53, 0x6F, 0x6C, 0x75, 0x74, 0x69, 0x6F, 0x6E, 0x30,
        0x1B, 0x04, 0x06, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x31, 0x11, 0x04,
        0x08, 0x4E, 0x61, 0x72, 0x62, 0x65, 0x72, 0x61, 0x6C, 0x04, 0x05, 0x47,
        0x61, 0x6D, 0x6D, 0x61);

my $search-result-entry-ber3 = Buf.new(
        0x30, 0x4A, 0x02, 0x01, 0x32, 0x64, 0x45, 0x04, 0x06, 0x74, 0x65, 0x73,
        0x74, 0x44, 0x4E, 0x30, 0x3B, 0x30, 0x1C, 0x04, 0x05, 0x66, 0x69, 0x72,
        0x73, 0x74, 0x31, 0x13, 0x04, 0x08, 0x53, 0x6F, 0x6C, 0x75, 0x74, 0x69,
        0x6F, 0x6E, 0x04, 0x07, 0x45, 0x70, 0x73, 0x69, 0x6C, 0x6F, 0x6E, 0x30,
        0x1B, 0x04, 0x06, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x31, 0x11, 0x04,
        0x08, 0x4E, 0x61, 0x72, 0x62, 0x65, 0x72, 0x61, 0x6C, 0x04, 0x05, 0x47,
        0x61, 0x6D, 0x6D, 0x61);

my $search-result-entry-ber4 = Buf.new(
        0x30, 0x4A, 0x02, 0x01, 0x32, 0x64, 0x45, 0x04, 0x06, 0x74, 0x65, 0x73,
        0x74, 0x44, 0x4E, 0x30, 0x3B, 0x30, 0x1C, 0x04, 0x05, 0x66, 0x69, 0x72,
        0x73, 0x74, 0x31, 0x13, 0x04, 0x08, 0x53, 0x6F, 0x6C, 0x75, 0x74, 0x69,
        0x6F, 0x6E, 0x04, 0x07, 0x45, 0x70, 0x73, 0x69, 0x6C, 0x6F, 0x6E, 0x30,
        0x1B, 0x04, 0x06, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x31, 0x11, 0x04,
        0x05, 0x47, 0x61, 0x6D, 0x6D, 0x61, 0x04, 0x08, 0x4E, 0x61, 0x72, 0x62,
        0x65, 0x72, 0x61, 0x6C);

my $search-result-entry = Cro::LDAP::Message.new(
        message-id => 50,
        protocol-op => ProtocolChoice.new((searchResEntry =>
                Cro::LDAP::Response::SearchEntry.new(
                        object-name => "testDN",
                        attributes => [
                            PartialAttribute.new(type => "first", vals => ("Epsilon", "Solution")),
                            PartialAttribute.new(type => "second", vals => ("Gamma", "Narberal"))
                        ])
        )));

my $serialized-result-entry = ASN::Serializer.serialize($search-result-entry);
ok $serialized-result-entry eqv $search-result-entry-ber1 ||
        $serialized-result-entry eqv $search-result-entry-ber2 ||
        $serialized-result-entry eqv $search-result-entry-ber3 ||
        $serialized-result-entry eqv $search-result-entry-ber4, "Search result entry is serialized";

my $parsed-search-result-entry = $parser.parse($search-result-entry-ber3);

subtest {
    ok $parsed-search-result-entry.message-id == 50;
    my $value = $parsed-search-result-entry.protocol-op.ASN-value.value;
    ok $value ~~ Cro::LDAP::Response::SearchEntry;
    ok $value.object-name eq "testDN";
    ok $value.attributes[0].type eq "first";
    ok $value.attributes[0].vals.keys.Set eqv set ("Epsilon", "Solution");
    ok $value.attributes[1].type eq "second";
    ok $value.attributes[1].vals.keys.Set eqv set ("Narberal", "Gamma");
}, "Search result entry is parsed";

# Search result done

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp searchResDone : {
#        resultCode success,
#        matchedDN '666F6F'H,
#        errorMessage ''H
#    }
#}

my $search-result-done = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((searchResDone => Cro::LDAP::Response::SearchDone.new(
                result-code => success,
                matched-dn => "foo",
                error-message => "")))
        );

my $search-result-done-ber = Buf.new(
        0x30, 0x0F, 0x02, 0x01, 0x05, 0x65, 0x0A, 0x0A,
        0x01, 0x00, 0x04, 0x03, 0x66, 0x6F, 0x6F, 0x04, 0x00);

is-deeply ASN::Serializer.serialize($search-result-done), $search-result-done-ber, "Search result done is serialized";

is-deeply $parser.parse($search-result-done-ber), $search-result-done, "Search result done is parsed";

# Search result reference

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp searchResRef : {
#        '6C6461703A2F2F686F7374622F4F553D50656F706C652C44433D4578616D706C652C44433D4E45543F3F737562'H,
#        '6C6461703A2F2F686F7374662F4F553D436F6E73756C74616E74732C4F553D50656F706C652C44433D4578616D706C652C44433D4E45543F3F737562'H
#    }
#}

my $search-result-reference = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((searchResRef => Cro::LDAP::Response::SearchRef.new(
                ("ldap://hostb/OU=People,DC=Example,DC=NET??sub",
                 "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub")
            )
        )
    )
);

my $search-result-reference-ber = Buf.new(
        0x30, 0x72, 0x02, 0x01, 0x05, 0x73, 0x6D, 0x04, 0x2D, 0x6C, 0x64,
        0x61, 0x70, 0x3A, 0x2F, 0x2F, 0x68, 0x6F, 0x73, 0x74, 0x62, 0x2F,
        0x4F, 0x55, 0x3D, 0x50, 0x65, 0x6F, 0x70, 0x6C, 0x65, 0x2C, 0x44,
        0x43, 0x3D, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2C, 0x44,
        0x43, 0x3D, 0x4E, 0x45, 0x54, 0x3F, 0x3F, 0x73, 0x75, 0x62, 0x04,
        0x3C, 0x6C, 0x64, 0x61, 0x70, 0x3A, 0x2F, 0x2F, 0x68, 0x6F, 0x73,
        0x74, 0x66, 0x2F, 0x4F, 0x55, 0x3D, 0x43, 0x6F, 0x6E, 0x73, 0x75,
        0x6C, 0x74, 0x61, 0x6E, 0x74, 0x73, 0x2C, 0x4F, 0x55, 0x3D, 0x50,
        0x65, 0x6F, 0x70, 0x6C, 0x65, 0x2C, 0x44, 0x43, 0x3D, 0x45, 0x78,
        0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2C, 0x44, 0x43, 0x3D, 0x4E, 0x45,
        0x54, 0x3F, 0x3F, 0x73, 0x75, 0x62);

is-deeply ASN::Serializer.serialize($search-result-reference), $search-result-reference-ber, "Search result reference is serialized";

is-deeply $parser.parse($search-result-reference-ber), $search-result-reference, "Search result reference is parsed";

# Modify request

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp searchResRef : {
#        '6C6461703A2F2F686F7374622F4F553D50656F706C652C44433D4578616D706C652C44433D4E45543F3F737562'H,
#        '6C6461703A2F2F686F7374662F4F553D436F6E73756C74616E74732C4F553D50656F706C652C44433D4578616D706C652C44433D4E45543F3F737562'H
#    }
#}

my $modify-req = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((modifyRequest => Cro::LDAP::Request::Modify.new(
                object => "dc=example,dc=com",
                modification => (
                    ModifyOp.new(:operation(ADD), modification => AttributeTypeAndValues.new(type => "type", vals => ['value'])),
                    ModifyOp.new(:operation(DELETE), modification => AttributeTypeAndValues.new(type => "type", vals => ['value']))
                )
            )
        )
    )
);

my $modify-req-ber = Buf.new(
        0x30, 0x46, 0x02, 0x01, 0x05, 0x66, 0x41, 0x04, 0x11, 0x64, 0x63,
        0x3D, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2C, 0x64, 0x63,
        0x3D, 0x63, 0x6F, 0x6D, 0x30, 0x2C, 0x30, 0x14, 0x0A, 0x01, 0x00,
        0x30, 0x0F, 0x04, 0x04, 0x74, 0x79, 0x70, 0x65, 0x31, 0x07, 0x04,
        0x05, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x30, 0x14, 0x0A, 0x01, 0x01,
        0x30, 0x0F, 0x04, 0x04, 0x74, 0x79, 0x70, 0x65, 0x31, 0x07, 0x04,
        0x05, 0x76, 0x61, 0x6C, 0x75, 0x65);

is-deeply ASN::Serializer.serialize($modify-req), $modify-req-ber, "Modify result reference is serialized";

is-deeply $parser.parse($modify-req-ber), $modify-req, "Modify result reference is parsed";

# Modify response

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp modifyResponse : {
#        resultCode operationsError,
#        matchedDN '666F6F'H,
#        errorMessage '4E6F2073756368206F626A656374'H
#    }
#}

my $modify-response = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((modifyResponse => Cro::LDAP::Response::Modify.new(
                result-code => operationsError,
                matched-dn => "foo",
                error-message => "No such object")))
        );

my $modify-response-ber = Buf.new(
        0x30, 0x1D, 0x02, 0x01, 0x05, 0x67, 0x18, 0x0A, 0x01, 0x01, 0x04, 0x03,
        0x66, 0x6F, 0x6F, 0x04, 0x0E, 0x4E, 0x6F, 0x20, 0x73, 0x75, 0x63, 0x68,
        0x20, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74);

is-deeply ASN::Serializer.serialize($modify-response), $modify-response-ber, "Modify response is serialized";

is-deeply $parser.parse($modify-response-ber), $modify-response, "Modify response is parsed";

# Abandon request

#value LDAPMessage ::= {
#    messageID 5,
#    protocolOp abandonRequest : 7
#}

my $abandon-request = Cro::LDAP::Message.new(
        message-id => 5,
        protocol-op => ProtocolChoice.new((abandonRequest => Cro::LDAP::Request::Abandon.new(7)))
        );

my $abandon-request-ber = Buf.new(0x30, 0x06, 0x02, 0x01, 0x05, 0x50, 0x01, 0x07);

is ASN::Serializer.serialize($abandon-request), $abandon-request-ber, "Abandon request is serialized";

is-deeply $parser.parse($abandon-request-ber), $abandon-request, "Abandon request is parsed";

done-testing;
