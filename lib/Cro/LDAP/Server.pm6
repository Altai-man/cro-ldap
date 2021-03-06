use Cro;
use Cro::TCP;
use Cro::TLS;
use Cro::Service;
use Cro::LDAP::Types;
use Cro::LDAP::Worker;
use Cro::LDAP::MessageParser;
use Cro::LDAP::MessageSerializer;

class Cro::LDAP::Server does Cro::Service {
    my class LDAPTransformer does Cro::Transform {
        has Cro::LDAP::Worker $.worker is required;

        method consumes() { Cro::LDAP::Message }
        method produces() { Cro::LDAP::Message }

        method transformer($request-stream) {
            supply {
                whenever $request-stream -> $request {
                    my $resp = $!worker.accept($request);
                    next unless $resp;

                    if $resp ~~ Cro::LDAP::Message {
                        emit $resp;
                        next;
                    }

                    if $resp ~~ Supply {
                        whenever $resp {
                            when Cro::LDAP::Message {
                                emit $_;
                            }
                            default {
                                emit Cro::LDAP::Message.new(
                                        message-id => $request.message-id,
                                        protocol-op => ProtocolOp.new($_));
                            }
                        }
                    } else {
                        emit Cro::LDAP::Message.new(
                                message-id => $request.message-id,
                                protocol-op => ProtocolOp.new($resp));

                    }
                }
            }
        }
    }

    only method new(:$worker!, :$host!, :$port!, :$label = "LDAP($port)", :%tls) {
        my $listener;
        if %tls {
            $listener = Cro::TLS::Listener.new(:$host, :$port, |%tls);
        } else {
            $listener = Cro::TCP::Listener.new(:$host, :$port);
        }
        my $transformer = LDAPTransformer.new(:$worker);
        Cro.compose(service-type => self.WHAT,
                :$label,
                $listener,
                Cro::LDAP::MessageParser,
                $transformer,
                Cro::LDAP::MessageSerializer);
    }
}
