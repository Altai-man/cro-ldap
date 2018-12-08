use ASN::Types;
#use Cro::LDAP::LDAPDN;

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

#class Cro::LDAP::Response::SearchEntry does Cro::LDAP::Response does ASNSequence {
#
#}