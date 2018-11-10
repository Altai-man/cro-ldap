subset Cro::LDAP::LDAPDN of Str;

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
