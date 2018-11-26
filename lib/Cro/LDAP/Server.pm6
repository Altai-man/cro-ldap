use Cro::LDAP::Request;
use Cro::LDAP::Response;
use Cro::LDAP::Worker;
use Cro::LDAP::RequestParser;
use Cro::LDAP::ResponseSerializer;
use Cro::Service;
use Cro::TCP;
use Cro;

class Cro::LDAP::Server does Cro::Service {
    my class LDAPTransformer does Cro::Transform {
        has Cro::LDAP::Worker $.server is required;

        method consumes() { Cro::LDAP::Message  }
        method produces() { Cro::LDAP::Response }

        method transformer($request-stream) {
            supply {
                whenever $request-stream -> $request {
                    $!server.accept($request);
                }
            }
        }
    }

    only method new(:$server!, :$host!, :$port!, :$label = "LDAP($port)") {
        my $listener = Cro::TCP::Listener.new(:$host, :$port);
        my $transformer = LDAPTransformer.new(:$server);
        Cro.compose(service-type => self.WHAT,
                :$label,
                $listener,
                Cro::LDAP::RequestParser,
                $transformer,
                Cro::LDAP::ResponseSerializer);

    }
}
