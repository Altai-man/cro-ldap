use ASN::Types;
use Cro::LDAP::Control;
use Cro::LDAP::ControlCarry;
use Cro::LDAP::Entry;
use Cro::LDAP::Extension;
use Cro::LDAP::Grammars;
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

class X::Cro::LDAP::Client::CannotAbandon is Exception {
    has Str $.op;

    method message() { "Cannot abandon ($!op) operation" }
}

class X::Cro::LDAP::Client::DoubleConnect is Exception {
    method message() { "An attempt to connect twice" }
}

class X::Cro::LDAP::Client::NotConnected is Exception {
    has Str $.op;

    method message() { "Cannot call $!op without an active connection" }
}

class X::Cro::LDAP::Client::UnrecognizedFilter is Exception {
    has Str $.str;

    method message() { "Filter pattern $!str was not recognized" }
}

class X::Cro::LDAP::Client::UnsuccessfulExtended is Exception {
    has ExtendedResponse $.response;

    method message() { "Was not able to process extended operation result, check Response object" }
}

class X::Cro::LDAP::Client::IncorrectOID is Exception {
    has Str $.str;

    method message() { "Incorrect control type syntax: '$!str'" }
}

class X::Cro::LDAP::Client::EmptyAttributeList is Exception {
    has Str $.dn;

    method message() { "Attempted to add an entry with no attributes: DN is $!dn" }
}

class X::Cro::LDAP::Client::IncorrectSearchAttribute is Exception {
    has $.attr;

    method message() { "Requested an attribute with illegal syntax in search request: '$!attr'" }
}

class X::Cro::LDAP::Client::NoCAFileForSecureConnection is Exception {
    has $.host;

    method message() { "Requested to connect to $!host over LDAPS, but CA file path was not passed" }
}

role Abandonable {
    method abandon { die X::Cro::LDAP::Client::CannotAbandon.new(:op<BIND>) }
}

role Abandonable[$client, $id] {
    method abandon {
        $client.abandon($id)
    }
}

class Cro::LDAP::Client {
    has atomicint $!message-counter = 1;
    has $!BIND-P;
    has Lock $!BIND-LOCK = Lock.new;

    my monitor Pipeline {
        has Supplier $!in;
        has Tap $!tap;
        has %!RESPONSE-TABLE;
        has Cro::LDAP::Client $!client;

        submethod BUILD(Supplier :$!in, Supply :$out!, Cro::LDAP::Client :$!client) {
            $!tap = supply {
                whenever $out -> $resp {
                    given $resp.protocol-op.key {
                        when 'searchResEntry'|'searchResRef' {
                            %!RESPONSE-TABLE{$resp.message-id}.emit: self!post-process($resp);
                        }
                        when 'searchResDone' {
                            %!RESPONSE-TABLE{$resp.message-id}.emit: self!post-process($resp);
                            %!RESPONSE-TABLE{$resp.message-id}.done;
                        }
                        default {
                            %!RESPONSE-TABLE{$resp.message-id}.keep(self!post-process($resp));
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
                    $entries.Supply but Abandonable[$!client, $request.message-id];
                }
                # Normal methods return a Promise
                default {
                    my $promise = $type eq 'bindRequest' ??
                            Promise.new but Abandonable !!
                            Promise.new but Abandonable[$!client, $request.message-id];
                    %!RESPONSE-TABLE{$request.message-id} = $promise;
                }
            }
        }

        method !post-process($message) {
            my $result;
            # Translate search results into user-friendly objects
            given $message.protocol-op.value -> $response {
                when $response ~~ SearchResultEntry {
                    my %attributes;
                    for $response.attributes.seq<> -> $attr {
                        my $values = $attr.vals.keys;
                        %attributes{$attr.type.decode} = $values.elems == 1 ?? $values[0] !! $values.Array;
                    }
                    $result = Cro::LDAP::Entry.new(dn => $response.object-name.decode, :%attributes);
                }
                when $response ~~ SearchResultReference {
                    $result = Cro::LDAP::Reference.new(refs => |$response.seq.map(*.decode));
                }
                when $response ~~ SearchResultDone {
                    $result = Cro::LDAP::Search::Done.new;
                }
                default {
                    $response.matched-dn = $response.matched-dn.decode;
                    $response.error-message = $response.error-message.decode;
                    $result = $response;
                }
            }
            # Attach server-side controls to response
            with $message.controls -> $controls {
                my @controls = $controls.seq<>;
                for @controls -> $control is rw {
                    my $ct = $control.control-type.decode;
                    my $type = %KNOWN-CONTROLS{$ct};
                    if $type ~~ Cro::LDAP::Control {
                        $control = $type.new($control);
                    } else {
                        $control = { control-type => $ct, control-value => $control.control-value, criticality => $control.criticality };
                    }
                }
                $result does Cro::LDAP::ControlCarry[@controls];
            } else {
                $result does Cro::LDAP::ControlCarry[()];
            }
            $result;
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

    multi method connect(Str :$host, Int :$port, Bool :$is-secure = False, :$ca-file --> Promise) {
        without self {
            return self.new.connect(:$host, :$port, :$is-secure, :$ca-file);
        }

        if $is-secure {
            die X::Cro::LDAP::Client::NoCAFileForSecureConnection.new(:$host) without $ca-file;
        }
        die X::Cro::LDAP::Client::DoubleConnect.new with $!pipeline;

        my $host-value = $host // 'localhost';
        my $port-value = $port // ($is-secure ?? 636 !! 389);

        my %ca := $ca-file ?? { :$ca-file } !! {};

        $!pipeline = self!get-pipeline($host-value, $port-value, %ca);
        Promise.kept(self);
    }
    multi method connect(Str $host, :$ca-file --> Promise) {
        my $url = Cro::LDAP::URL.parse($host);
        self.connect(
                |(host => $url.hostname with $url.hostname),
                |(port => $url.port with $url.port),
                is-secure => $url.is-secure, :$ca-file);
    }

    method disconnect {
        with $!pipeline {
            $!pipeline.close;
            $!pipeline = Nil;
        }
    }

    # Operations
    method bind(Str :$name = "", :$password = "", :control(:$controls) --> BindResponse) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<bind>) unless self;

        my $new-bind-p = Promise.new;
        my $bind-promise = cas($!BIND-P, Any, $new-bind-p);
        if ($bind-promise === Any) {
            my $resp = await self!wrap-request({
                my $authentication = AuthenticationChoice.new($password ~~ Str ??
                        simple => $password !!
                        sasl => SaslCredentials.new(|$password));
                BindRequest.new(version => 3, :$name, :$authentication);
            }, :$controls);
            $!BIND-LOCK.protect({
                $new-bind-p.keep;
                cas($!BIND-P, $new-bind-p, Any);
            });
            $resp;
        } else {
            await $bind-promise;
            self.bind(:$name, :$password, :$controls);
        }
    }

    method !queue-after-bind() {
        with $!BIND-P {
            await $_;
        }
    }

    method unbind(:control(:$controls) is copy) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<unbind>) unless self;
        self!queue-after-bind;

        # Remove critical status from unbind controls
        with $controls {
            $_ = .map( -> $c {
                if $c ~~ Associative {
                    $c<critical>:delete;
                } elsif $c ~~ Control {
                    $c.criticality = False;
                }
                $c;
            }).List;
        }
        self!wrap-request({ UnbindRequest.new }, :$controls);
        $!pipeline.close;
        $!pipeline = Nil;
    }

    method add($dn, :@attrs, :control(:$controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<add>) unless self;
        die X::Cro::LDAP::Client::EmptyAttributeList.new(:$dn) if @attrs.elems < 1;
        self!queue-after-bind;

        self!wrap-request({
            my @attributes;
            for @@attrs {
                @attributes.push: AttributeListBottom.new(
                        type => .key,
                        vals => ASNSetOf[ASN::Types::OctetString].new(.value ~~ Buf ?? .value !! |.value));
            }
            AddRequest.new(entry => $dn,
                    attributes => ASNSequenceOf[AttributeListBottom].new(seq => @attributes));
        }, :$controls);
    }

    method delete($dn, :control(:$controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<delete>) unless self;
        self!queue-after-bind;

        self!wrap-request({ DelRequest.new($dn) }, :$controls);
    }

    method compare(Str $entry, Str $attribute-desc, Str $assertion-value, :control($controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<compare>) unless self;
        self!queue-after-bind;

        self!wrap-request({
            my $ava = AttributeValueAssertion.new(:$attribute-desc, :$assertion-value);
            CompareRequest.new(:$entry, :$ava);
        }, :$controls);
    }

    my %MODS = add => add, replace => replace, delete => delete;

    multi method modify($object, *%changes, :control(:$controls)) {
        self.modify($object, %changes.List, :$controls);
    }
    multi method modify($object, @changes, :control(:$controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<modify>) unless self;
        self!queue-after-bind;

        my ModificationBottom @modification;
        for @changes -> $change {
            my $operation = %MODS{$change.key};
            for @($change.value) -> $attr {
                my ($type, $vals) = $attr ~~ Str ?? ($attr, ()) !! ($attr.key, $attr.value);
                my $modification = AttributeTypeAndValues.new(
                        :$type, :vals(ASNSetOf[ASN::Types::OctetString].new(|$vals)));
                @modification.push: ModificationBottom.new(:$operation, :$modification);
            }
        }
        my $modification = ASNSequenceOf[ModificationBottom].new(seq => @modification);
        self!wrap-request({

            ModifyRequest.new(:$object, :$modification)
        }, :$controls);
    }

    method modifyDN(:$dn!, :$new-dn!, :$delete = True, :$new-superior, :control(:$controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op('modify DN')) unless self;
        self!queue-after-bind;

        self!wrap-request({
            ModifyDNRequest.new(
                    entry => $dn,
                    newrdn => $new-dn,
                    deleteoldrdn => $delete,
                    :$new-superior);
        }, :$controls);
    }

    method search(Str :$dn!, Str :$filter is copy = '(objectclass=*)',
            Scope :$scope = wholeSubtree,
            DerefAliases :$deref-aliases = derefFindingBaseObj,
            Int :$size-limit = 0, Int :$time-limit = 0,
            Bool :$types-only = False,
            :@attributes = [], :control(:$controls)) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<search>) unless self;
        self!queue-after-bind;

        # Prepare filter
        $filter = '(' ~ $filter unless $filter.starts-with('(');
        $filter = $filter ~ ')' unless $filter.ends-with(')');
        my $filter-object = Cro::LDAP::Search.parse($filter);
        die X::Cro::LDAP::Client::UnrecognizedFilter.new(str => $filter) without $filter-object;

        # Prepare attributes
        for @attributes -> $attribute {
            unless self!check-attribute-syntax($attribute) {
                die X::Cro::LDAP::Client::IncorrectSearchAttribute.new(attr => $attribute);
            }
        }
        my $attributes = ASNSequenceOf[Any].new(seq => @attributes);

        # Create request
        self!wrap-request({
            SearchRequest.new(
                    base-object => $dn, :$scope, :$deref-aliases,
                    :$size-limit, :$time-limit, :$types-only, :$attributes,
                    filter => $filter-object);
        }, :$controls);
    }
    method !check-attribute-syntax($attribute) {
        $attribute eq '*'|'1.1' or Attributes.parse($attribute, :rule<attributeDescription>);
    }

    method abandon($id, :control(:$controls)) {
        self!queue-after-bind;
        self!wrap-request({ AbandonRequest.new($id) }, :$controls);
    }

    method root-DSE(*@custom-attrs --> Promise) {
        my @attributes = <altServer namingContexts supportedControl
                    supportedExtension supportedFeatures supportedLDAPVersion
                    supportedSASLMechanisms subschemaSubentry>;
        @attributes.push: $_ for @custom-attrs;

        Promise(supply {
            my %attrs;
            whenever self.search(:dn(''), :filter<(objectclass=*)>, :@attributes) {
                when Cro::LDAP::Entry {
                    %attrs.push: .attributes;
                }
                when Cro::LDAP::Search::Done {
                    emit Cro::LDAP::RootDSE.new(%attrs);
                    done;
                }
            }
        });
    }

    method schema(Str $dn? --> Promise) {
        my $base = $dn // self.root-DSE()<subschemaSubentry> // 'cn=schema';
        my @attributes = <objectClasses attributeTypes matchingRules matchingRuleUse
                 dITStructureRules dITContentRules nameForms
                 ldapSyntaxes extendedAttributeInfo>;
        Promise(supply {
            my %attrs;
            whenever self.search(:dn($base), scope => baseObject,
                                 filter => '(objectClass=subschema)', :@attributes) {
                when Cro::LDAP::Entry {
                    %attrs.push: .attributes;
                }
                when Cro::LDAP::Search::Done {
                    emit Cro::LDAP::Schema.new(%attrs);
                    done;
                }
            }
        })
    }

    multi method extend(Cro::LDAP::Extension $op) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<extended>) unless self;
        self!queue-after-bind;

        my $resp = self!wrap-request({ $op.message });
        Promise(supply {
            whenever $resp {
                if .result-code == success {
                    emit $op.callback($_);
                } else {
                    die X::Cro::LDAP::Client::UnsuccessfulExtended.new(response => $_);
                }
            }
        })
    }

    multi method extend(Str $request-name, Buf $request-value?) {
        die X::Cro::LDAP::Client::NotConnected.new(:op<extended>) unless self;
        self!queue-after-bind;

        without Common.parse($request-name, :rule<numericoid>) {
            die X::Cro::LDAP::Client::IncorrectOID.new(:str($request-name));
        }

        self!wrap-request({ ExtendedRequest.new(:$request-name, :$request-value) });
    }

    method startTLS() {
        die "Not Yet Implemented";
        self.extend("1.3.6.1.4.1.1466.20037");
    }

    multi method sync(@entries where { $_.all ~~ Cro::LDAP::Entry }) {
        my @responses;
        for @entries -> Cro::LDAP::Entry $entry {
            @responses.push: self.sync($entry);
        }
        @responses;
    }

    multi method sync(Cro::LDAP::Entry $entry) {
        given $entry.operation {
            when LDIF::Op::ldif-add {
                self.add($entry.dn, attrs => $entry.attributes.List);
            }
            when LDIF::Op::ldif-delete {
                self.delete($entry.dn);
            }
            when LDIF::Op::ldif-moddn|LDIF::Op::ldif-modrdn {
                self.modifyDN(
                        :dn($entry.dn), :new-dn($entry<newrdn>),
                        :delete($entry<delete-on-rdn>),
                        :new-superior($entry<newsuperior>));
            }
            when LDIF::Op::ldif-modify {
                self.modify($entry.dn, |$entry.attributes);
            }
            default {
                self.add($entry.dn, attrs => $entry.attributes.List)
            }
        }
    }

    method !wrap-request(&make-message, :$controls) {
        my $message = make-message;
        $!pipeline.send-request(self!wrap-with-envelope($message, :$controls));
    }

    method !wrap-with-envelope($request, :controls($raw-controls)) {
        my $controls = self!process-controls($raw-controls);
        my $message-id = $!message-counter⚛++;
        my $choice = $request.^name.subst(/(\w)/, *.lc, :1st);
        $choice = 'modDNRequest' if $request ~~ ModifyDNRequest;
        $choice = 'extendedReq' if $request ~~ ExtendedRequest;
        Cro::LDAP::Message.new(:$message-id, protocol-op => ProtocolOp.new(($choice => $request)), :$controls);
    }

    method !process-controls($raw-controls) {
        my @seq;
        for $raw-controls<> // [] {
            when Cro::LDAP::Control {
                @seq.push: .to-control;
            }
            when Associative {
                my $control-type = self!check-control($_);
                my $control = Control.new(:$control-type,
                        criticality => $_<critical> // False,
                        control-value => $_<value> // Str);
                @seq.push: $control;
            }
            default {
                warn "Expected Control or Associative, encountered $_.^name() instead, skipping";
            }
        }
        ASNSequenceOf[Control].new(:@seq);
    }
    method !check-control($control) {
        with $control<type> && (Common.parse($control<type>, :rule<numericoid>)) {
            return ~$_;
        } else {
            die X::Cro::LDAP::Client::IncorrectOID.new(str => ($control<type> // 'no type specified at all'));
        }
    }
}