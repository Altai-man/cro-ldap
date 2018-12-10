use ASN::Types;

enum ResultCode is export (
        :success(0),
        :operationsError(1)
);

role Cro::LDAP::Response {}

class Cro::LDAP::Response::Bind does Cro::LDAP::Response does ASNSequence {
    has ResultCode $.result-code;
    has Str $.matched-dn is OctetString;
    has Str $.error-message is OctetString;
    has Str @.referral is OctetString is optional;
    has Str $.server-sasl-creds is OctetString is optional is tagged(7);

    method ASN-order() { <$!result-code $!matched-dn $!error-message @!referral $!server-sasl-creds> }
    method ASN-tag-value { 1 }
}

class PartialAttribute does ASNSequence {
    has Str $.type is OctetString;
    has Set $.vals;

    method ASN-order { <$!type $!vals> }
}

class Cro::LDAP::Response::SearchEntry does Cro::LDAP::Response does ASNSequence {
    has Str $.object-name is OctetString;
    has PartialAttribute @.attributes;

    method ASN-order { <$!object-name @!attributes> }
}
