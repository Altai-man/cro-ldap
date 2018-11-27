use Cro::Transform;
use Cro::LDAP::Message;
use Cro::LDAP::Response;
use Cro::TCP;

class Cro::LDAP::ResponseSerializer does Cro::Transform {
    has atomicint $!message-counter = 0;

    method consumes() { Cro::LDAP::Message }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $responses) {
        supply {
            whenever $responses -> $response {
                emit Cro::TCP::Message.new(data => self!wrap($response).serialize);
            }
            CATCH {
                default {.note}
            }
        }
    }

    my %response-types = 'Cro::LDAP::Response::Bind' => 'bindResponse';

    method !wrap($response) {
        my $message-id = $!message-counter ⚛+= 2;
        Cro::LDAP::Message.new(
                :$message-id,
                protocol-op => %response-types{$response.^name} => $response);
    }
}
