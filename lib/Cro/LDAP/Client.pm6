use OO::Monitors;
use ASN::Types;
use Cro::LDAP::Search;
use Cro::LDAP::Types;
use Cro::LDAP::RequestSerializer;
use Cro::LDAP::ResponseParser;
use Cro::LDAP::URL;

class Cro::LDAP::Client {
    has IO::Socket::Async $!socket;
    has atomicint $!message-counter = 1;

    my monitor Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has %!RESPONSE-TABLE;
        has $!lock = Lock.new;

        submethod BUILD(:$!in, :$out!) {
            $!tap = supply {
                whenever $out -> $resp {
                    given $resp.protocol-op.key {
                        when 'searchResEntry'|'searchResRef' {

                            %!RESPONSE-TABLE{$resp.message-id}.emit: $resp.protocol-op.value;
                        }
                        when 'searchResDone' {
                            %!RESPONSE-TABLE{$resp.message-id}.done;
                        }
                        default {
                            %!RESPONSE-TABLE{$resp.message-id}.keep($resp.protocol-op.value);
                        }
                    }
                }
            }.tap;
        }

        method send-request(Cro::LDAP::Message $request) {
            $!in.emit($request);
            given $request.protocol-op.key {
                when 'searchRequest' {
                    my $entries = Supplier.new;
                    %!RESPONSE-TABLE{$request.message-id} = $entries;
                    $entries.Supply;
                }
                default {
                    %!RESPONSE-TABLE{$request.message-id} = Promise.new;
                }
            }
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

    multi method connect(Str $host, Int $port) {
        IO::Socket::Async.connect($host, $port).then(-> $promise {
            $!socket = $promise.result;
            $!pipeline = self!get-pipeline(:$host, :$port);
        });
    }

    multi method connect(Str $host) {
        my $url = Cro::LDAP::URL.parse($host);
        self.connect($url.hostname, $url.port);
    }

    method bind(Str :$name = "", :$password = "") {
        self!wrap-request({
            my $authentication = AuthenticationChoice.new($password ~~ Str ??
                    simple => ASN::Types::OctetString.new($password) !!
                    sasl => SaslCredentials.new(|$password));
            BindRequest.new(version => 3, :$name, :$authentication);
        });
    }

    method add($dn, :@attrs) {
        self!wrap-request({
            my $attributes = Array[AttributeListBottom].new;
            for @@attrs {
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

    method compare(Str $entry, Str $attribute-desc, Str $assertion-value) {
        self!wrap-request({
            my $ava = AttributeValueAssertion.new(:$attribute-desc, :$assertion-value);
            CompareRequest.new(:$entry, :$ava);
        });
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

    method search(Str :$base!, Str :$filter!,
            Scope :$scope = wholeSubtree,
            DerefAliases :$deref-aliases = derefFindingBaseObj,
            Int :$size-limit = 0, Int :$time-limit = 0,
            Bool :$types-only = False,
            :$attributes = Array[Str].new()) {
        my $filter-object = Cro::LDAP::Search.parse($filter);
        self!wrap-request({
            SearchRequest.new(
                    base-object => $base,
                    :$scope, :$deref-aliases,
                    :$size-limit, :$time-limit,
                    :$types-only, :$attributes,
                    filter => $filter-object);
        });
    }

    method !wrap-request(&make-message) {
         my $message = make-message;
         $!pipeline.send-request(self!wrap-with-envelope($message));
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