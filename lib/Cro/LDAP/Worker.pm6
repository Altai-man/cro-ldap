use Cro::LDAP::Types;

role Cro::LDAP::Worker {
    method bind($req --> BindResponse) {...}
    method search($req --> Supply) {...}
    method unbind($req) {...}

    method accept(Cro::LDAP::Message $request) {
        my $op = $request.protocol-op.ASN-value;
        given $op.value {
            when BindRequest {
                my $res = self.bind($_);
                bindResponse => $res;
            }
            when UnbindRequest {
                self.unbind($_);
                Nil;
            }
            when SearchRequest {
                supply {
                    whenever self.search($_) {
                        emit $_;
                    }
                }
            }
            default {
                die "Not yet implemented message is sent: $op.key()";
            }
        }
    }
}
