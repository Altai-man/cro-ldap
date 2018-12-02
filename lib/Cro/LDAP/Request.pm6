use ASN::BER;
use ASN::Types;
use Cro::LDAP::Authentication;
use Cro::LDAP::LDAPDN;

class Control does ASNType {
    has Cro::LDAP::LDAPDN $.control-type;
    has Bool $.criticality is default-value(False);
    has ASN::OctetString $.control-value is optional;

    method ASN-order { <$!control-type $!criticality $!control-value> }
}

class Cro::LDAP::Request::Bind does ASNType {
    has Int $.version is required;
    has Cro::LDAP::LDAPDN $.name is required;
    has $.authentication is choice-of(
            simple => (0 => ASN::OctetString),
            sasl   => (3 => Cro::LDAP::Authentication::SaslCredentials)) is required;

    method ASN-order { <$!version $!name $!authentication> }
    method ASN-tag-value { 0 } # [APPLICATION 0]
}

class Cro::LDAP::Request::Unbind is ASN-Null {
    method ASN-tag-value { 2 }
}
