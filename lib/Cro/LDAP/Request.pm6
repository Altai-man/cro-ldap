use ASN::Types;
use Cro::LDAP::Authentication;

class Control does ASNSequence {
    has Str $.control-type is OctetString;
    has Bool $.criticality is default-value(False);
    has $.control-value is OctetString is optional;

    method ASN-order { <$!control-type $!criticality $!control-value> }
}

class AuthChoice does ASNChoice {
    method ASN-choice {
        { simple => (0 => ASN::Types::OctetString),
          sasl   => (3 => Cro::LDAP::Authentication::SaslCredentials) }
    }
}

class Cro::LDAP::Request::Bind does ASNSequence {
    has Int $.version is required;
    has Str $.name is OctetString is required;
    has AuthChoice $.authentication is required;

    method ASN-order { <$!version $!name $!authentication> }
    method ASN-tag-value { 0 } # [APPLICATION 0]
}

class Cro::LDAP::Request::Unbind is ASN-Null {
    method ASN-tag-value { 2 }
}

enum SearchScope is export <BaseObject SingleLevel WholeSubtree>;
enum DerefAlias is export <NeverDerefAliases DererInSearching DerefFindingBaseObj DerefAlways>;

class AttributeValueAssertion does ASNSequence {
    has Str $.attribute-desc is OctetString;
    has Str $.assertion-value is OctetString;

    method ASN-order { <$!attribute-desc $!assertion-value> }
}

class Filter {...}

class Filter does ASNChoice {
    method ASN-choice {
        { and => (0 => Set),
          not => (2 => Filter),
          equalityMatch => (3 => AttributeValueAssertion) }
    }
}

class Cro::LDAP::Request::Search does ASNSequence {
    has Str $.base-object is OctetString;
    has SearchScope $.scope;
    has DerefAlias $.deref-aliases;
    has Int $.size-limit;
    has Int $.time-limit;
    has Bool $.types-only;
    has Filter $.filter;
    has Str @.attributes is OctetString;

    method ASN-order { <$!base-object $!scope $!deref-aliases $!size-limit $!time-limit $!types-only $!filter @!attributes> }
    method ASN-tag-value { 3 }
}

enum ModifyAction is export <ADD DELETE REPLACE>;

class AttributeTypeAndValues does ASNSequence {
    has Str $.type is OctetString;
    has ASNSetOf[ASN::Types::OctetString] $.vals;

    method new(Str :$type, Positional :$vals) {
        self.bless(:$type, vals => ASNSetOf[ASN::Types::OctetString].new($vals));
    }

    method ASN-order { <$!type $!vals> }
}

class ModifyOp does ASNSequence {
    has ModifyAction $.operation;
    has AttributeTypeAndValues $.modification;

    method ASN-order { <$!operation $!modification> }
}

class Cro::LDAP::Request::Modify does ASNSequence {
    has Str $.object is OctetString;
    has ModifyOp @.modification;

    method ASN-order { <$!object @!modification> }
    method ASN-tag-value { 6 }
}

class Cro::LDAP::Request::Add does ASNSequence {
    has Str $.entry is OctetString;
    has AttributeTypeAndValues @.attributes;

    method ASN-order { <$!entry @!attributes> }
    method ASN-tag-value { 8 }
}

class Cro::LDAP::Request::Abandon is Int {
    method ASN-tag-value { 16 }
}