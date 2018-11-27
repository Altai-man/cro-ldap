use Cro::LDAP::Message;
use Cro::LDAP::Request;
use Cro::LDAP::Response;

role Cro::LDAP::Worker {
    method bind(Cro::LDAP::Request::Bind $req --> Cro::LDAP::Response::Bind) {...}

    method accept(Cro::LDAP::Message $request --> Cro::LDAP::Response) {
        my $op = $request.protocol-op.value;
        given $op {
            when Cro::LDAP::Request::Bind {
                self.bind($op);
            }
            default {
                die "Not yet implemented message is sent: $request.protocol-op().key()";
            }
        }
    }
}
