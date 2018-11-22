use Cro::LDAP::LDAPDN;
use Cro::LDAP::Authentication;
use Cro::LDAP::ProtocolOp;
use Cro::LDAP::LDAPDN;
use ASN::BER;
use ASN::Types;

class Cro::LDAP::Request::Bind {...}

class Cro::LDAP::Request does ASNType does Cro::LDAP::ProtocolOp {
    has $.protocol-op is choice-of(
            bindRequest => Cro::LDAP::Request::Bind,
    );

    # FIXME [0] Controls are missing
    method ASN-order { <$!message-id $!protocol-op> }
}

class Cro::LDAP::Request::Bind does ASNType {
    has Int $.version is required;
    has Cro::LDAP::LDAPDN $.name is required;
    has $.authentication is choice-of(
            simple => (0 => Str),
            sasl   => (3 => Cro::LDAP::Authentication::SaslCredentials)) is required;

    method ASN-order { <$!version $!name $!authentication> }
    method ASN-tag-value { 0 } # [APPLICATION 0]
}
