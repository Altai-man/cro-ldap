use ASN::Types;
use Cro::LDAP::Search;
use Cro::LDAP::Types;
use Cro::LDAP::MessageSerializer;
use Cro::LDAP::MessageParser;
use Cro::LDAP::URL;
use Cro::LDAP::Schema;
use Cro::LDAP::Entry;
use Cro::LDAP::Reference;
use Cro::LDAP::RootDSE;
use Cro::TLS;
use IO::Socket::Async::SSL;
use OO::Monitors;

class X::Cro::LDAP::Client::DoubleConnect is Exception {
    method message() { "An attempt to connect twice" }
}

class X::Cro::LDAP::Client::NotConnected is Exception {
    has Str $.op;

    method message() { "Cannot call $!op without an active connection" }
}

class X::Cro::LDAP::Client::UnrecognizedFilter {
    has Str $.str;

    method message() { "Filter pattern $!str was not recognized" }
}

role Abandonable[:$client, :$id] {
    method abandon { $client.abandon($id) }
}

class Cro::LDAP::Client {
    has $.host = 'localhost';
    has $.port = 389;
    has atomicint $!message-counter = 1;

    my monitor Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has %!RESPONSE-TABLE;
        has $!lock = Lock.new;
        has Cro::LDAP::Client $!client;

        submethod BUILD(Supplier :$!in, Supply :$out!, Cro::LDAP::Client :$!client) {
            $!tap = supply {
                whenever $out -> $resp {
                    given $resp.protocol-op.key {
                        when 'searchResEntry'|'searchResRef' {
                            %!RESPONSE-TABLE{$resp.message-id}.emit: self!post-process($resp.protocol-op.value);
                        }
                        when 'searchResDone' {
                            %!RESPONSE-TABLE{$resp.message-id}.done;
                        }
                        default {
                            %!RESPONSE-TABLE{$resp.message-id}.keep(self!post-process($resp.protocol-op.value));
                        }
                    }
                }
            }.tap;
        }

        method send-request(Cro::LDAP::Message $request) {
            $!in.emit($request);
            given $request.protocol-op.key -> $type {
                # Do nothing as unbind request does not have a response
                when $type eq 'unbindRequest' {}
                # Search request returns a Supply, not a single Promise
                when $type eq 'searchRequest' {
                    my $entries = Supplier.new;
                    %!RESPONSE-TABLE{$request.message-id} = $entries;
                    $entries.Supply but Abandonable[client => $!client, id => $request.message-id];
                }
                # Normal methods return a Promise
                default {
                    my $promise = $type eq 'bindRequest' ??
                            Promise.new !!
                            Promise.new but Abandonable[client => $!client, id => $request.message-id];
                    %!RESPONSE-TABLE{$request.message-id} = $promise;
                }
            }
        }

        method !post-process($response) {
            given $response {
                when SearchResultEntry {
                    my %attributes;
                    for @($response.attributes) -> $attr {
                        my $values = $attr.vals.keys;
                        %attributes{$attr.type} = $values.elems == 1 ?? $values[0] !! $values;
                    }
                    return Cro::LDAP::Entry.new(
                            dn => $response.object-name,
                            :%attributes);
                }
                when SearchResultReference {
                    return Cro::LDAP::Reference.new(refs => |$_.seq);
                }
                default {
                    return $response;
                }
            }
        }

        method close() {
            $!in.done;
            %!RESPONSE-TABLE = hash;
        }
    }

    has Pipeline $!pipeline;

    method !get-pipeline(Str $host, Int $port, %ca --> Pipeline) {
        my $connector := %ca ?? Cro::TLS::Connector !! Cro::TCP::Connector;
        my @parts = Cro::LDAP::MessageSerializer, $connector, Cro::LDAP::MessageParser;
        my $connect-chain = Cro.compose(|@parts);
        my $in = Supplier::Preserving.new;
        my $out = $connect-chain.establish($in.Supply, :$host, :$port, |%ca);
        Pipeline.new(:$in, :$out, client => self);
    }

    # Connection-related methods

    multi method connect(Cro::LDAP::Client:U: Str :$host, Int :$port, :$is-secure = False, :$ca-file --> Promise) {
        self.new.connect(:$host, :$port, :$is-secure, :$ca-file);
    }
    multi method connect(Cro::LDAP::Client:D: Str :$host, Int :$port, Bool :$is-secure = False, :$ca-file --> Promise) {
        with $!pipeline {
            die X::Cro::LDAP::Client::DoubleConnect.new;
        }

        my $host-value = $host // $!host;
        my $port-value = $port // $!port;

        my $socket = $is-secure ?? IO::Socket::Async::SSL !! IO::Socket::Async;
        my %ca := $ca-file ?? { :$ca-file } !! {};

        $socket.connect($host-value, $port-value, |%ca).then(-> $promise {
            $!pipeline = self!get-pipeline($host-value, $port-value, %ca);
            self;
        });
    }
    multi method connect(Str $host, :$ca-file --> Promise) {
        my $url = Cro::LDAP::URL.parse($host);
        self.connect(
                |(host => $url.hostname with $url.hostname),
                |(port => $url.port with $url.port),
                is-secure => $url.is-secure, :$ca-file);
    }

    method disconnect() {
        $!pipeline.close;
        $!pipeline = Nil;
    }

    # Operations

    method bind(Str :$name = "", :$password = "", :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<bind>) unless self;

        self!wrap-request({
            my $authentication = AuthenticationChoice.new($password ~~ Str ??
                    simple => ASN::Types::OctetString.new($password) !!
                    sasl => SaslCredentials.new(|$password));
            BindRequest.new(version => 3, :$name, :$authentication);
        }, :@controls);
    }

    method unbind() {
        die X::Cro::LDAP::Client::NotConnected.new(:op<unbind>) unless self;

        self!wrap-request({ UnbindRequest.new });
    }

    method add($dn, :@attrs, :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<add>) unless self;

        self!wrap-request({
            my $attributes = Array[AttributeListBottom].new;
            for @@attrs {
                $attributes.push: AttributeListBottom.new(
                        type => .key,
                        vals => ASNSetOf[ASN::Types::OctetString].new(.value));
            }
            AddRequest.new(entry => $dn, :$attributes);
        }, :@controls);
    }

    method delete($dn, :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<delete>) unless self;

        self!wrap-request({ DelRequest.new($dn) }, :@controls);
    }

    method compare(Str $entry, Str $attribute-desc, Str $assertion-value, :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<compare>) unless self;

        self!wrap-request({
            my $ava = AttributeValueAssertion.new(:$attribute-desc, :$assertion-value);
            CompareRequest.new(:$entry, :$ava);
        }, :@controls);
    }

    my %MODS = add => add, replace => replace, delete => delete;

    multi method modify($object, *%changes, :@controls) {
        self.modify($object, %changes.List, :@controls);
    }
    multi method modify($object, @changes, :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<modify>) unless self;

        my ModificationBottom @modification;
        for @changes -> $change {
            my $modification = AttributeTypeAndValues.new(type => $change.value<type>, vals => ASNSetOf[ASN::Types::OctetString].new(|($change.value<vals> // ())));
            @modification.push: ModificationBottom.new(operation => %MODS{$change.key}, :$modification);
        }
        self!wrap-request({ ModifyRequest.new(:$object, :@modification) }, :@controls);
    }

    method modifyDN(:$dn!, :$new-dn!, :$delete = True, :$new-superior, :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op('modify DN')) unless self;

        self!wrap-request({
            ModifyDNRequest.new(
                    entry => $dn,
                    newrdn => $new-dn,
                    deleteoldrdn => $delete,
                    :$new-superior);
        }, :@controls);
    }

    method search(Str :$dn!, Str :$filter! is copy,
            Scope :$scope = wholeSubtree,
            DerefAliases :$deref-aliases = derefFindingBaseObj,
            Int :$size-limit = 0, Int :$time-limit = 0,
            Bool :$types-only = False,
            :$attributes = Array[Str].new(), :@controls) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<search>) unless self;

        $filter = '(' ~ $filter unless $filter.starts-with('(');
        $filter = $filter ~ ')' unless $filter.ends-with(')');

        my $filter-object = Cro::LDAP::Search.parse($filter);

        die X::Cro::LDAP::Client::UnrecognizedFilter.new(str => $filter) without $filter-object;

        self!wrap-request({
            SearchRequest.new(
                    base-object => $dn, :$scope, :$deref-aliases,
                    :$size-limit, :$time-limit, :$types-only, :$attributes,
                    filter => $filter-object);
        }, :@controls);
    }

    method abandon($id, :@controls) {
        self!wrap-request({ AbandonRequest.new($id) }, :@controls);
    }

    method root-DSE(*@attrs) {
        my @defs = <altServer namingContexts supportedControl
                    supportedExtension supportedFeatures supportedLDAPVersion
                    supportedSASLMechanisms subschemaSubentry>;
        my $attributes = Array[Str].new(|@defs);
        $attributes.push: $_ for @attrs;

        my $entry = await self.search(:dn(''), :filter<(objectclass=*)>, :$attributes);
        Cro::LDAP::RootDSE.new($entry.attributes);
    }

    method schema(Str $dn?) {
        my $base = $dn // self.root-DSE()<subschemaSubentry> // 'cn=schema';
        my $attributes = Array[Str].new(
                <objectClasses attributeTypes matchingRules matchingRuleUse
                 dITStructureRules dITContentRules nameForms
                 ldapSyntaxes extendedAttributeInfo>);
        my $entry = await self.search(:dn($base), scope => baseObject,
                                      filter => '(objectClass=subschema)', :$attributes);
        Cro::LDAP::Schema.new($entry.attributes);
    }

    method extend($message) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<extended>) unless self;
    }

    method !wrap-request(&make-message, :@controls) {
         my $message = make-message;
         $!pipeline.send-request(self!wrap-with-envelope($message, :@controls));
    }

    method !wrap-with-envelope($request, :controls(@raw-controls)) {
        my @controls := self!process-controls(@raw-controls);
        my $message-id = $!message-counter⚛++;
        my $choice = $request.^name.subst(/(\w)/, *.lc, :1st);
        $choice = 'modDNRequest' if $request ~~ ModifyDNRequest;
        Cro::LDAP::Message.new(:$message-id, protocol-op => ProtocolOp.new(($choice => $request)), :@controls);
    }
    method !process-controls(@raw-controls) {
        my @controls := Array[Control].new;
        for @raw-controls {
            when Control {
                @controls.push: $_;
            }
            when Associative {
                my $control = Control.new(control-type => $_<type>,
                        criticality => $_<critical> // False,
                        control-value => $_<value> // Str);
                @controls.push: $control;
            }
            default {
                warn "Expected Control or Associative, encountered $_.^name() instead, skipping";
            }
        }
        @controls;
    }
}