use ASN::Serializer;
use Cro::TCP;
use Cro::Transform;
use Cro::LDAP::Types;

class Cro::LDAP::ResponseSerializer does Cro::Transform {
    has atomicint $!message-counter = 0;

    method consumes() { Cro::LDAP::Message }
    method produces() { Cro::TCP::Message  }

    method transformer(Supply $responses) {
        my $serializer = ASN::Serializer.new;
        supply {
            whenever $responses -> $response {
                emit Cro::TCP::Message.new(data => $serializer.serialize(self!wrap($response)));
            }
            CATCH {
                default {.note}
            }
        }
    }

    my %response-types = 'BindResponse' => 'bindResponse';

    method !wrap($response) {
        my $message-id = $!message-counter ⚛+= 2;
        Cro::LDAP::Message.new(
                :$message-id,
                protocol-op => ProtocolOp.new((%response-types{$response.^name} => $response)));
    }
}
