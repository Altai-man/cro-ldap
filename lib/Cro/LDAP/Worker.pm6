use Cro::LDAP::Message;
use Cro::LDAP::Request;
use Cro::LDAP::Response;

role Cro::LDAP::Worker {
    method bind(Cro::LDAP::Request::Bind $req --> Cro::LDAP::Response::Bind) {...}

    method accept(Cro::LDAP::Message $request --> Cro::LDAP::Response) {
        my $op = $request.protocol-op.ASN-value;
        given $op.value {
            when Cro::LDAP::Request::Bind {
                self.bind($op.value);
            }
            default {
                die "Not yet implemented message is sent: $op.key()";
            }
        }
    }
}
