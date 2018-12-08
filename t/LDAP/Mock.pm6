use ASN::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Worker;
use Cro::LDAP::Response;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind(Cro::LDAP::Request::Bind $req --> Cro::LDAP::Response::Bind) {
        Cro::LDAP::Response::Bind.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }
}
