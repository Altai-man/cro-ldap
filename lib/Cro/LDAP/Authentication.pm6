use ASN::BER;

class Cro::LDAP::Authentication::SaslCredentials {
    has $.mechanism;
    has $.credentials;
}
