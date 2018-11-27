use ASN::BER;
use ASN::Types;
use Cro::LDAP::LDAPDN;

enum ResultCode is export (
        :success(0),
        :operationsError(1)
);

class Cro::LDAP::Response::Bind does ASNType {
    has ResultCode $.result-code;
    has Cro::LDAP::LDAPDN $.matched-dn;
    has ASN::OctetString $.error-message;
    has Cro::LDAP::LDAPURL @.referral is optional;
    has ASN::OctetString $.server-sasl-creds is optional is tagged(7);

    method ASN-order() { <$!result-code $!matched-dn $!error-message @!referral $!server-sasl-creds> }
    method ASN-tag-value { 1 }
}
