use ASN::Parser;
use ASN::Serializer;
use Cro::LDAP::Types;
use ASN::Types;

role Cro::LDAP::Control is Control {
    multi method new(Control $c) {
        self.bless(control-type => $c.control-type.decode, criticality => $c.criticality, control-value => $c.control-value);
    }
}

class Cro::LDAP::Control::Assertion does Cro::LDAP::Control {
    has $.assertion;

    method to-control($assertion) {
        my $filter-object = Cro::LDAP::Search.parse($assertion);
        my $value = ASN::Serializer.serialize($filter-object).encode;
        Control.new(control-type => "1.3.6.1.1.12", :criticality, :$value);
    }
}

class Cro::LDAP::Control::DontUseCopy does Cro::LDAP::Control {
    method to-control() { Control.new(control-type => "1.3.6.1.1.22", :criticality) }
}

class Cro::LDAP::Control::ProxyAuth does Cro::LDAP::Control {
    has Str $.value = '';

    multi method new(:$value) { self.bless(:$value, control-type => "2.16.840.1.113730.3.4.18", :criticality) }

    method to-control() { Control.new(control-type => "2.16.840.1.113730.3.4.18", :criticality, control-value => $!value) }
}

class Cro::LDAP::Control::Relax {
    method to-control() { Control.new(control-type => "1.3.6.1.4.1.4203.666.5.12", :criticality) }
}

class Cro::LDAP::Control::Paged does Cro::LDAP::Control {
    has Int $.size is rw;
    has $.cookie is rw;

    my class SearchControlValue does ASNSequence {
        has Int $.size is rw;
        has $.cookie is OctetString is rw;

        method ASN-order { <$!size $!cookie> }
    }

    multi method new(:$size!, :$cookie = Buf.new) {
        my $paged = SearchControlValue.new(:$size, :$cookie);
        self.bless(:$size, :$cookie, control-type => "1.2.840.113556.1.4.319", :!criticality,
                control-value => ASN::Serializer.serialize($paged));
    }
    multi method new(Control $control) {
        my $value = ASN::Parser.new(type => SearchControlValue).parse($control.control-value);
        self.bless(size => $value.size, cookie => $value.cookie,
                   control-type => "1.2.840.113556.1.4.319", :!criticality, control-value => $control.control-value);
    }

    method to-control() {
        my $paged = SearchControlValue.new(:$!size, :$!cookie);
        Control.new(control-type => "1.2.840.113556.1.4.319", :!criticality, control-value => ASN::Serializer.serialize($paged));
    }
}

our %KNOWN-CONTROLS is export = "1.2.840.113556.1.4.319" => Cro::LDAP::Control::Paged,
        "1.3.6.1.4.1.4203.666.5.12" => Cro::LDAP::Control::Relax,
        "2.16.840.1.113730.3.4.18" => Cro::LDAP::Control::ProxyAuth,
        "1.3.6.1.1.22" => Cro::LDAP::Control::DontUseCopy,
        "1.3.6.1.1.12" => Cro::LDAP::Control::Assertion;