use Cro::LDAP::Server;
use Cro::LDAP::Worker;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind(Cro::LDAP::Request::Bind $req --> Cro::LDAP::Response::Bind) {
        Cro::LDAP::Response::Bind.new;
    }
}
