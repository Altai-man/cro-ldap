use Cro::LDAP::Types;

role Cro::LDAP::Worker {
    method bind($req --> BindResponse) {...}
    method unbind($req) {...}
    method search($req --> Supply) {...}
    method add($req --> AddResponse) {...}

    method accept(Cro::LDAP::Message $request) {
        my $op = $request.protocol-op.ASN-value;
        given $op.value {
            when BindRequest {
                bindResponse => self.bind($_);
            }
            when UnbindRequest {
                self.unbind($_);
                Nil;
            }
            when AddRequest {
                addResponse => self.add($_);
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
