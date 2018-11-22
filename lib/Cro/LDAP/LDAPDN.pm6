use ASN::Types;

class Cro::LDAP::LDAPDN is ASN::OctetString {}

class AttributeTypeAndValue {
    has Str $.type;
    has Str $.value;
}

class RelativeDistinguishedName {
    has AttributeTypeAndValue $.values;
}

class DisginguishedName {
    has RelativeDistinguishedName @.relatives;
}
