use Cro;
use ASN::Types;
use ASN::META BEGIN { 'file', slurp %?RESOURCES<ldap.asn> };

class Cro::LDAP::Search::Done {}

class Cro::LDAP::Message is LDAPMessage does Cro::Message {
    method trace-output(--> Str) {
        "LDAP MSG [{self.message-id}] {self.protocol-op.choice-value.key.tc}"
    }
}

my $map := MY::.pairs.grep({ .key ~~ /^ <[a..zA..Z]>/ && .key ne <EXPORT GLOBALish>.any}).Map;

sub EXPORT() {
    $map;
}
