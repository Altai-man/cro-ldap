use Cro::LDAP::Types;

role Cro::LDAP::Worker {
    method bind($req, :@controls --> BindResponse) {...}
    method unbind($req) {...}
    method search($req, :@controls --> Supply) {...}
    method add($req, :@controls --> AddResponse) {...}
    method delete($req, :@controls --> DelResponse) {...}
    method compare($req, :@controls --> CompareResponse) {...}
    method modify($req, :@controls --> ModifyResponse) {...}
    method modifyDN($req, :@controls --> ModifyDNResponse) {...}
    method abandon($req, :@controls) {...}

    method accept(Cro::LDAP::Message $request) {
        my $op = $request.protocol-op.ASN-value;
        my @controls := $request.controls;
        given $op.value {
            when BindRequest {
                bindResponse => self.bind($_, :@controls);
            }
            when UnbindRequest {
                self.unbind($_);
                Nil;
            }
            when AddRequest {
                addResponse => self.add($_, :@controls);
            }
            when DelRequest {
                delResponse => self.delete($_, :@controls);
            }
            when CompareRequest {
                compareResponse => self.compare($_, :@controls);
            }
            when ModifyRequest {
                modifyResponse => self.modify($_, :@controls);
            }
            when ModifyDNRequest {
                modDNResponse => self.modifyDN($_, :@controls);
            }
            when SearchRequest {
                supply {
                    whenever self.search($_, :@controls) {
                        emit $_;
                    }
                }
            }
            when Int { # AbandonRequest is just Int
                self.abandon($_, :@controls);
                Nil;
            }
            default {
                die "Not yet implemented message is sent: $op.key()";
            }
        }
    }
}
