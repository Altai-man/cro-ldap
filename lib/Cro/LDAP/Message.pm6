use ASN::BER;
use ASN::Types;
use Cro;
use Cro::LDAP::Request;
use Cro::LDAP::Response;

class ProtocolChoice does ASNChoice {
    has $.value;

    method new($value) { self.bless(:$value) }

    method ASN-choice {
        { bindRequest => Cro::LDAP::Request::Bind,
        bindResponse => Cro::LDAP::Response::Bind,
        unbindRequest => Cro::LDAP::Request::Unbind,
        searchRequest => Cro::LDAP::Request::Search,
        abandonRequest => Cro::LDAP::Request::Abandon }
    }

    method ASN-value { $!value }
}

class Cro::LDAP::Message does ASNSequence does Cro::Message {
    has Int $.message-id is required;
    has ProtocolChoice $.protocol-op;
    has Control @.controls is optional is tagged(0);

    method ASN-order { <$!message-id $!protocol-op @!controls> }
}
