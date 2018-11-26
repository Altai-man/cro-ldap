use ASN::BER;
use ASN::Types;
use Cro::LDAP::Request;
use Cro::LDAP::Response;

class Cro::LDAP::Message does ASNType {
    has Int $.message-id is required;
    has $.protocol-op is choice-of(
            bindRequest => Cro::LDAP::Request::Bind,
    );
    has Control @.controls is optional is tagged(0);

    method ASN-order { <$!message-id $!protocol-op @!controls> }
}
