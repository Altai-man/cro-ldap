use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::RequestSerializer;
use Cro::LDAP::ResponseParser;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;
    has atomicint $!message-counter = 1;

    my class Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has $!next-response-vow;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out {
                    my $vow = $!next-response-vow;
                    $!next-response-vow = Nil;
                    $vow.keep($_.protocol-op.ASN-value.value);
                }
            }.tap;
        }

        method send-request(Cro::LDAP::Message $request) {
            my $next-response-promise = Promise.new;
            $!next-response-vow = $next-response-promise.vow;
            $!in.emit($request);
            $next-response-promise
        }
    }

    has Pipeline $!pipeline;

    method !get-pipeline(:$host, :$port) {
        my @parts;
        push @parts, Cro::LDAP::RequestSerializer;
        push @parts, Cro::TCP::Connector;
        push @parts, Cro::LDAP::ResponseParser;
        my $connector = Cro.compose(|@parts);
        my $in = Supplier::Preserving.new;
        my $out = $connector.establish($in.Supply, :$host, :$port);
        Pipeline.new(:$in, :$out);
    }

    method connect(Str $host, Int $port) {
        IO::Socket::Async.connect($host, $port).then(-> $promise {
            $!socket = $promise.result;
            $!pipeline = self!get-pipeline(:$host, :$port);
        });
    }

    method bind(Str $name, :$auth = "") {
        self!wrap-request({
            my $authentication = AuthenticationChoice.new($auth ~~ Str ??
                    simple => ASN::Types::OctetString.new($auth) !!
                    sasl => SaslCredentials.new(|$auth));
            BindRequest.new(
                    version => 3, :$name,
                    :$authentication);
        });
    }

    method add($dn, @attributes) {
        self!wrap-request({
            my $attributes = Array[AttributeListBottom].new;
            for @attributes {
                $attributes.push: AttributeListBottom.new(
                        type => .key,
                        vals => ASNSetOf[ASN::Types::OctetString].new(.value));
            }
            AddRequest.new(entry => $dn, :$attributes);
        });
    }

    method delete($dn) {
        self!wrap-request({ DelRequest.new($dn) });
    }

    method compare($entry, :$ava!) {
        self!wrap-request({ CompareRequest.new(:$entry, :$ava) });
    }

    my %MODS = add => add, replace => replace, delete => delete;

    method modify($object, @changes) {
        my ModificationBottom @modification;
        for @changes -> $change {
            my $modification = AttributeTypeAndValues.new(type => $change.value<type>, vals => ASNSetOf[ASN::Types::OctetString].new(|($change.value<vals> // ())));
            @modification.push: ModificationBottom.new(operation => %MODS{$change.key}, :$modification);
        }
        self!wrap-request({ ModifyRequest.new(:$object, :@modification) });
    }

    method modifyDN(:$dn!, :$new-dn!, :$delete = True, :$new-superior) {
        self!wrap-request({
            ModifyDNRequest.new(
                    entry => $dn,
                    newrdn => $new-dn,
                    deleteoldrdn => $delete,
                    :$new-superior);
        });
    }

    method !wrap-request(&make-message) {
        Promise(supply {
            my $message = make-message;
            whenever $!pipeline.send-request(self!wrap-with-envelope($message)) {
                emit $_;
            }
        })
    }

    method !wrap-with-envelope($request) {
        my $message-id = $!message-counter⚛++;
        my $choice = $request.^name.subst(/(\w)/, *.lc, :1st);
        if $request ~~ ModifyDNRequest {
            $choice = 'modDNRequest';
        }
        Cro::LDAP::Message.new(
                :$message-id,
                protocol-op => ProtocolOp.new(($choice => $request)));
    }
}