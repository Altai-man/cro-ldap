use ASN::Types;

enum ResultCode is export (
        :success(0),
        :operationsError(1)
);

my role Cro::LDAP::LDAPResult does ASNSequence {
    has ResultCode $.result-code;
    has Str $.matched-dn is OctetString;
    has Str $.error-message is OctetString;
    has Str @.referral is OctetString is optional;

    method ASN-order { <$!result-code $!matched-dn $!error-message @!referral> }
}

role Cro::LDAP::Response {}

class Cro::LDAP::Response::Bind does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    has Str $.server-sasl-creds is OctetString is optional is tagged(7);

    method ASN-order() { <$!result-code $!matched-dn $!error-message @!referral $!server-sasl-creds> }
    method ASN-tag-value { 1 }
}

class PartialAttribute does ASNSequence {
    has Str $.type is OctetString;
    has ASNSetOf[ASN::Types::OctetString] $.vals;

    method new(Str :$type, Positional :$vals) {
        self.bless(:$type, vals => ASNSetOf[ASN::Types::OctetString].new($vals));
    }

    method ASN-order { <$!type $!vals> }
}

class Cro::LDAP::Response::SearchEntry does Cro::LDAP::Response does ASNSequence {
    has Str $.object-name is OctetString;
    has PartialAttribute @.attributes;

    method ASN-order { <$!object-name @!attributes> }
    method ASN-tag-value { 4 }
}

class Cro::LDAP::Response::SearchDone does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    method ASN-tag-value { 5 }
}

class Cro::LDAP::Response::SearchRef does Positional[ASN::Types::OctetString] {
    has @.urls;

    method new(@urls) { self.bless(:@urls) }

    method iterator(Cro::LDAP::Response::SearchRef:D:){ @!urls.iterator }
    method ASN-tag-value { 19 }
}

class Cro::LDAP::Response::Modify does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    method ASN-tag-value { 7 }
}

class Cro::LDAP::Response::Add does Cro::LDAP::Response does Cro::LDAP::LDAPResult  {
    method ASN-tag-value { 9 }
}