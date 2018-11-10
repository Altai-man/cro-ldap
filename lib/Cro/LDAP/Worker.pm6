use Cro::LDAP::Request;
use Cro::LDAP::Response;

role Cro::LDAP::Worker {
    method bind(Cro::LDAP::Request::Bind $req --> Cro::LDAP::Response::Bind) {...}

    method accept(Cro::LDAP::Request $request --> Cro::LDAP::Response) {
        if $request ~~ Cro::LDAP::Request::Bind {
            self.bind($request);
        } else {
            die "NYI";
        }
    }
}
