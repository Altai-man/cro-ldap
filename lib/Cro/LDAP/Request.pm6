use Cro::LDAP::LDAPDN;
use Cro::LDAP::Authentication;
use Cro::LDAP::ProtocolOp;
use ASN::BER;
use ASN::Types;

class Control does ASNType {
    has Cro::LDAP::LDAPDN $.control-type;
    has Bool $.criticality is default-value(False);
    has ASN::OctetString $.control-value is optional;

    method ASN-order { <$!control-type $!criticality $!control-value> }
}

class Cro::LDAP::Request::Bind {...}

class Cro::LDAP::Request does ASNType does Cro::LDAP::ProtocolOp {
    has $.protocol-op is choice-of(
            bindRequest => Cro::LDAP::Request::Bind,
    );
    has Control @.controls is optional is tagged(0);

    method ASN-order { <$!message-id $!protocol-op @!controls> }
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
