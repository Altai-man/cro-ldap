use Cro::Uri;
use Cro::LDAP::Grammars;
use Cro::LDAP::Search;

# Common regexes

grammar DN is export {
    token TOP { <relativeDN>* % ',' }
    regex relativeDN { <attributeTypeAndValue>+? % "+" }
    regex attributeTypeAndValue { <attrType> "=" <attrValue> }
    token attrType { <Common::descr> | <Common::numericoid> }
    regex attrValue { <string> | <hexstr> }

    regex string { [ [<leadchar> | <pair>] [ [ <stringchar> | <pair> ]*? [ <trailchar> | <pair> ] ]? ]? }

    token pair { "\\" [ "\\" | <special> | <hexpair> ] }
    token special { <escaped> | <[\ #=]> }
    token escaped { <["+,;<>]> }
    token hexstr { '#' <hexpair> }
    token hexpair { <Common::hex> ** 2 }

    token leadchar { <LUTF1> | <Common::UTFMB> }
    token LUTF1 { <[ \x01..\x1F \x21 \x24..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }

    token trailchar { <TUTF1> | <Common::UTFMB> }
    token TUTF1 { <[ \x01..\x1F \x21 \x23..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }

    token stringchar { <SUTF1> | <Common::UTFMB> }
    token SUTF1 { <[ \x01..\x21 \x23..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }
}

class Cro::LDAP::URL {
    has Str $.hostname;
    has Int $.port;
    has Str @.DN;
    has Str @.attributes;
    has Str $.scope;
    has Str $.filter;
    has Str @.extensions;

    grammar Grammar {
        regex TOP {
            ^
            <prefix>
            <entity>?
            <query>?
            $
        }

        token entity {
            $<host> = <Cro::Uri::GenericParser::host>
            [ ":" $<port> = <Cro::Uri::GenericParser::port> ]?
        }

        regex query {
            "/" [ <DN::relativeDN>* % ',' ] [ "?" <attributes>?
                [ "?" <scope>?
                    ["?" <Cro::LDAP::Search::Grammar::filter>?
                        [ "?" <extensions> ]?
                    ]?
                ]?
            ]?
        }

        regex attributes { <attrdesc>+ % ',' }
        regex attrdesc   { <selector>+ % ',' }
        regex selector   { <attributeSelector> }
        regex attributeSelector { <Attributes::attributeDescription> | <selectorSpecial> }
        token selectorSpecial { '1.1' | '*' }

        token scope { :i "base" | "one" | "sub" }

        regex extensions { <extension>* % ',' }
        regex extension { "!"? <extype> [ "=" <exvalue> ]? }
        regex extype { <Attributes::oid> }
        # TODO Check correctness according to RFC 4511, 4.1.2
        regex exvalue { .*? }

        token prefix { :i "ldap://" }
    }

    class Actions {
        method TOP($/) {
            my ($scope, $filter, @attributes, @DN, @extensions) = ('base', 'objectClass=*');
            my $host = $<entity><host>;
            my $port = $<entity><port> // 389;
            with $<query><DN::relativeDN> {
                @DN = $_>>.Str;
            }
            with $<query><attributes> {
                @attributes = $_<attrdesc>>>.Str;
            }
            with $<query><scope> {
                $scope = ~$_.lc;
            }
            with $<query><Cro::LDAP::Search::Grammar::filter> {
                $filter = ~$_<filtercomp>;
            }
            with $<query><extensions> {
                @extensions = $_<extension>>>.Str;
            }

            make Cro::LDAP::URL.new:
                    hostname => ~$<entity><host>,
                    port => $port.Int, :@DN, :@attributes,
                    :$scope, :$filter, :@extensions;
        }
    }

    method parse(Str $url) {
        Grammar.parse($url, :actions(Actions)).made;
    }
}