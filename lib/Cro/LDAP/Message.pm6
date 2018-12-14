use ASN::Types;
use Cro;
use Cro::LDAP::Request;
use Cro::LDAP::Response;

class ProtocolChoice does ASNChoice {
    method ASN-choice {
        { bindRequest => Cro::LDAP::Request::Bind,
        bindResponse => Cro::LDAP::Response::Bind,
        unbindRequest => Cro::LDAP::Request::Unbind,
        searchRequest => Cro::LDAP::Request::Search,
        searchResEntry => Cro::LDAP::Response::SearchEntry,
        searchResDone => Cro::LDAP::Response::SearchDone,
        searchResRef => Cro::LDAP::Response::SearchRef,
        modifyRequest => Cro::LDAP::Request::Modify,
        modifyResponse => Cro::LDAP::Response::Modify,
        addRequest => Cro::LDAP::Request::Add,
        addResponse => Cro::LDAP::Response::Add,
        delRequest => Cro::LDAP::Request::Del,
        delResponse => Cro::LDAP::Response::Del,
        abandonRequest => Cro::LDAP::Request::Abandon }
    }
}

class Cro::LDAP::Message does ASNSequence does Cro::Message {
    has Int $.message-id is required;
    has ProtocolChoice $.protocol-op;
    has Control @.controls is optional is tagged(0);

    method ASN-order { <$!message-id $!protocol-op @!controls> }
}
