use Cro::LDAP::Types;

role Cro::LDAP::Worker {
    method bind($req --> BindResponse) {...}

    method accept(Cro::LDAP::Message $request) {
        my $op = $request.protocol-op.ASN-value;
        given $op.value {
            when BindRequest {
                my $res = self.bind($_);
                return bindResponse => $res;
            }
            default {
                die "Not yet implemented message is sent: $op.key()";
            }
        }
    }
}
