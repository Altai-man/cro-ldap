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
        my @controls;
        @controls = .seq<> with $request.controls<>;
        given $op.value {
            when BindRequest {
                my $resp = self.bind($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                bindResponse => $resp;
            }
            when UnbindRequest {
                self.unbind($request);
                Nil;
            }
            when AddRequest {
                my $resp = self.add($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                addResponse => $resp;
            }
            when DelRequest {
                my $resp = self.delete($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                delResponse => $resp;
            }
            when CompareRequest {
                my $resp = self.compare($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                compareResponse => $resp;
            }
            when ModifyRequest {
                my $resp = self.modify($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                modifyResponse => $resp;
            }
            when ModifyDNRequest {
                my $resp = self.modifyDN($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                modDNResponse => $resp;
            }
            when SearchRequest {
                supply {
                    whenever self.search($request, :@controls) {
                        emit $_;
                    }
                }
            }
            when ExtendedRequest {
                my $resp = self.extended($request, :@controls);
                return $resp if $resp ~~ Cro::LDAP::Message;
                extendedResp => $resp;
            }
            when Int { # AbandonRequest is just Int
                self.abandon($request, :@controls);
                Nil;
            }
            default {
                die "Not yet implemented message is sent: $op.key()";
            }
        }
    }
}
