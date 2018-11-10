use Cro::LDAP::Response;
use Cro::LDAP::Request;
use Cro::TCP;

my %type-to-class =
    0 => Cro::LDAP::Request::Bind,
    1 => Cro::LDAP::Response::Bind;

class Cro::LDAP::GenericParser {
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
                    my $class-to-emit = %type-to-class{$type};
                    with $class-to-emit {
                        emit $_.deserialize($data.subbuf(1));
                    }
                    else {
                        die "NYI code: $type";
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