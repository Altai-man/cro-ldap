use ASN::Serializer;
use Cro::LDAP::Types;

class Cro::LDAP::Control is Control {
}

class Cro::LDAP::Control::Assertion is Control {
    has $.assertion;

    method new($assertion) {
        my $filter-object = Cro::LDAP::Search.parse($assertion);
        my $value = ASN::Serializer.serialize($filter-object).encode;
        Control.new(control-type => "1.3.6.1.1.12", :criticality, :$value);
    }
}

class Cro::LDAP::Control::DontUseCopy is Control {
    method new() { Control.new(control-type => "1.3.6.1.1.22", :criticality) }
}

class Cro::LDAP::Control::ProxyAuth is Control {
    method new(Str $value = "") {
        Control.new(control-type => "2.16.840.1.113730.3.4.18", :criticality, :$value)
    }
}
class Cro::LDAP::Control::Relax is Control {
    method new() { Control.new(control-type => "1.3.6.1.4.1.4203.666.5.12", :criticality) }
}
