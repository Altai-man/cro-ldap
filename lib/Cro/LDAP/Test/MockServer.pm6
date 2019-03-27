use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::Worker;

class MockLDAPWorker does Cro::LDAP::Worker {
    method success-result($type) {
        return $type.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }

    method bind($req --> BindResponse) {
        self.success-result(BindResponse);
    }

    method unbind($req) {}

    method add($req) {
        self.success-result(AddResponse);
    }

    method delete($req) {
        self.success-result(DelResponse);
    }

    method search($req) {
        supply {
            emit (searchResEntry => SearchResultEntry.new(object-name => "foo",
                    attributes => Array[PartialAttributeListBottom].new(
                            PartialAttributeListBottom.new(type => "first", vals => ASNSetOf[ASN::Types::OctetString].new("Epsilon", "Solution")),
                            PartialAttributeListBottom.new(type => "second", vals => ASNSetOf[ASN::Types::OctetString].new("Gamma", "Narberal"))
                    )));
            emit (searchResDone => SearchResultDone.new(
                    result-code => success,
                    matched-dn => "",
                    error-message => ""));
        }
    }
}