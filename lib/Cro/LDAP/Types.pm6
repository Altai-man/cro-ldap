use Cro;
use ASN::Types;
use ASN::META <file docs/ldap.asn plugin resources/asn-plugin>;

role Cro::LDAP::Response {}

class Cro::LDAP::Message is LDAPMessage does Cro::Message {
    method trace-output(--> Str) {
        "LDAP MSG [{self.message-id}] {self.protocol-op.choice-value.key.tc}"
    }
}

my $map = %(|(MY::.map({ .value ~~ ResultCode ?? (.key => .value) !! Any } ).grep(*.defined)));
$map.push: |%(|(MY::.map( { .value ~~ ProtocolType ?? (.key => .value) !! Any } ).grep(*.defined)));
$map.push: |%(|(MY::.map( { .value ~~ DerefAliases ?? (.key => .value) !! Any } ).grep(*.defined)));

$map.push: (neverDerefAliases => neverDerefAliases);
$map.push: (wholeSubtree => wholeSubtree);

$map.push: (EqualityMatch => EqualityMatch);
$map.push: (AttributeListBottom => AttributeListBottom);
$map.push: (PartialAttributeListBottom => PartialAttributeListBottom);

$map.push: (add => add);
$map.push: (delete => delete);

$map.push: (AttributeTypeAndValues => AttributeTypeAndValues);
$map.push: (Modification => Modification);
$map.push: (ModificationBottom => ModificationBottom);
$map.push: (BindRequest => BindRequest);
$map.push: (BindResponse => BindResponse);
$map.push: (UnbindRequest => UnbindRequest);
$map.push: (SearchRequest => SearchRequest);
$map.push: (SearchResultEntry => SearchResultEntry);
$map.push: (SearchResultDone => SearchResultDone);
$map.push: (SearchResultReference => SearchResultReference);
$map.push: (ModifyRequest => ModifyRequest);
$map.push: (ModifyResponse => ModifyResponse);
$map.push: (AddRequest => AddRequest);
$map.push: (AddResponse => AddResponse);
$map.push: (DelRequest => DelRequest);
$map.push: (DelResponse => DelResponse);
$map.push: (ModifyDNRequest => ModifyDNRequest);
$map.push: (ModifyDNResponse => ModifyDNResponse);
$map.push: (CompareRequest => CompareRequest);
$map.push: (CompareResponse => CompareResponse);
$map.push: (AbandonRequest => AbandonRequest);
$map.push: (Control => Control);
$map.push: (ProtocolOp => ProtocolOp);
$map.push: (Filter => Filter);
$map.push: (AttributeValueAssertion => AttributeValueAssertion);
$map.push: (AuthenticationChoice => AuthenticationChoice);

sub EXPORT() {
    $map;
}