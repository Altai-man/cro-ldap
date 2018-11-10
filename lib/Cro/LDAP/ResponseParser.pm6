use Cro::Transform;
use Cro::TCP;
use Cro::LDAP::Response;

class Cro::LDAP::ResponseParser does Cro::Transform {
    method consumes() { Cro::TCP::Message   }
    method produces() { Cro::LDAP::Response }

    method transformer(Supply $in) {
        supply {
            my enum Expecting <Type Length Value>;
            my $expecting = Type;
            my $length;

            my sub decode-message(Blob $data) {
                my $typeOctet = $data[0];
                # 96 is 0b01100000, we are checking if it
                # is a constructed application type
                if $typeOctet +& 96 eq 96 {
                    my $type = $typeOctet +^ 96;
                    given $type {
                        when 1 {
                            emit Cro::LDAP::Response::Bind.deserialize($data.subbuf(1));
                        }
                        default {
                            die "NYI code: $type";
                        }
                    }
                } else {
                    die "Bad value $data";
                }
            }

            whenever $in -> Cro::TCP::Message $packet {
                my Blob $data = $packet.data;
                loop {
                    $_ = $expecting;
                    when Type {
                        # Sequence code
                        my $type = $data[0];
                        unless $type == 30 {
                            die 'Malformed message envelope';
                        }
                        $data = $data.subbuf(1);
                        $expecting = Length;
                        proceed;
                    }
                    when Length {
                        my $lengthFirstOctet = $data[0];
                        if $lengthFirstOctet <= 128 {
                            $length = $lengthFirstOctet +^ 128;
                        } else { die "NYI" }
                        $data = $data.subbuf(1);
                        $expecting = Value;
                        proceed;
                    }
                    when Value {
                        if $data.elems < $length {
                            emit decode-message($data);
                        } else { die "NYI" }
                    }
                }
            }
        }
    }
}