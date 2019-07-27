use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::Worker;

class MockLDAPWorker does Cro::LDAP::Worker {
    has @.CHECKS;

    method accept(Cro::LDAP::Message $request) {
        my $op = $request.protocol-op.ASN-value;
        $_[1].keep with @!CHECKS.grep({ $_[0]($op.value) }).first;
        self.Cro::LDAP::Worker::accept($request);
    }

    method bind(BindRequest $req, :@controls --> BindResponse) {
        my $error-message;
        my $result-code = success;

        if $req.name.elems == 0 {
            $error-message = "Anonymous bind";
        } elsif $req.authentication.value.elems == 0 {
            $error-message = "Unauthenticated bind";
        } else {
            $error-message = "Normal bind";
        }

        if $req.name.decode eq "dn=no-more" {
            $result-code = busy;
        }

        BindResponse.new(:$result-code, :matched-dn(''), :$error-message, :server-sasl-creds<CustomCreds>);
    }

    method unbind($req) {}

    method add($req, :@controls) {
        # Special test data can be obtained with controls passed
        with @controls {
            for @controls -> $control {
                if $control.control-type.decode eq "1.3.6.1.1.22" && $control.criticality {
                    return AddResponse.new(
                            result-code => compareFalse,
                            matched-dn => $req.entry.decode.comb.reverse.join,
                            error-message => '');
                }
            }
        }

        my $error-message = '';
        without $req.attributes.seq.first(*.type.decode eq 'jpegphoto') {
            for @($req.attributes.seq) -> $attr {
                $error-message ~= $attr.type.decode;
                $error-message ~= $attr.vals.map(*.key.decode).Set;
            }
        }

        AddResponse.new(
                result-code => success, matched-dn => $req.entry, :$error-message);
    }

    method delete($req, :@controls) {
        DelResponse.new(result-code => success, matched-dn => $req.value, error-message => "")
    }

    method compare($req, :@controls) {
        my $error-message = "$req.ava().attribute-desc().decode()=$req.ava().assertion-value().decode()";
        CompareResponse.new(result-code => compareTrue, matched-dn => $req.entry, :$error-message)
    }

    method modify($req, :@controls) {
        my $error-message;
        for $req.modification.seq<> {
            given .operation -> $mod {
                $error-message ~= "add" when $mod ~~ add;
                $error-message ~= "replace" when $mod ~~ replace;
                $error-message ~= "delete" when $mod ~~ delete;
                $error-message ~= .modification.type.decode;
                $error-message ~= [~] .modification.vals.map(*.key.decode).Set;
            }

        }
        ModifyResponse.new(result-code => success, matched-dn => $req.object, :$error-message);
    }

    method modifyDN($req, :@controls) {
        my $error-message = $req.newrdn ~ ($req.new-superior // Blob.new);
        ModifyDNResponse.new(result-code => success, matched-dn => $req.entry, :$error-message);
    }

    method search($req, :@controls) {
        supply {
            if $req.base-object.elems == 0 {
                emit (searchResEntry => SearchResultEntry.new(object-name => "",
                    attributes => ASNSequenceOf[PartialAttributeListBottom].new(seq => [
                            PartialAttributeListBottom.new(type => "supportedExtension", vals => ASNSetOf[ASN::Types::OctetString].new("1.3.6.1.4.1.4203.1.11.1")),
                            PartialAttributeListBottom.new(type => "customAttr1", vals => ASNSetOf[ASN::Types::OctetString].new("foo")),
                            PartialAttributeListBottom.new(type => "customAttr2", vals => ASNSetOf[ASN::Types::OctetString].new("bar"))]
                    )));
                emit (searchResDone => SearchResultDone.new(
                    result-code => success,
                    matched-dn => "",
                    error-message => ""));
                done;
            }

            my $i = 1;
            $i = 10 if $req.filter.key ~~ 'present'|'substrings';
            emit (searchResEntry => SearchResultEntry.new(object-name => "foo",
                    attributes => ASNSequenceOf[PartialAttributeListBottom].new(seq => [
                            PartialAttributeListBottom.new(type => "first", vals => ASNSetOf[ASN::Types::OctetString].new("Epsilon", "Solution")),
                            PartialAttributeListBottom.new(type => "second", vals => ASNSetOf[ASN::Types::OctetString].new("Gamma", "Narberal"))]
                    ))) for ^$i;


            if $req.filter.key ~~ 'substrings' {
                emit (searchResRef => SearchResultReference.new(
                        seq => ["ldap://hostb/OU=People,DC=Example,DC=NET??sub",
                                "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub"])) for ^5;
            }

            emit (searchResDone => SearchResultDone.new(
                    result-code => success,
                    matched-dn => "",
                    error-message => ""));
        }
    }

    method abandon($req, :@controls) {}
}