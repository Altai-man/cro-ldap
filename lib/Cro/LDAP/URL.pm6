no precompilation;
use Cro::Uri;

grammar Common {
    token UTFMB { <UTF2> | <UTF3> | <UTF4> }
    token UTF0 { <[ \x80..\xBF ]> }
    token UTF2 { <[ \xC2..\xDF ]> <UTF0> }
    token UTF3 {
        | [ <[\xE0]> <[\xA0..\xBF]> <UTF0> ]
        | [ <[\xE1..\xEC]> <UTF0> ** 2 ]
        | [ \xED <[\x80..\x9F]> <UTF0> ]
        | [ <[\xEE..\xEF]> <UTF0> ** 2 ]
    }
    token UTF4 {
        | [ \xF0 <[\x90..\xBF]> <UTF0> ** 2 ]
        | [ <[\xF1..\xF3]> <UTF0> ** 3 ]
        | \xF4 [ <[\x80..\x8F]> <UTF0> ** 2 ]
    }

    token hex { <digit> | <[\x41..\x46 \x61..\x66]> }

    regex descr { <leadkey> <keychar>*? }
    token leadkey { <[a..zA..Z]> }
    token keychar { <[-a..zA..Z0..9]> }

    token numericoid { <number> [ "." <number> ]? }
    token number { <[0..9]> | [ <[1..9]> <[0..9]> ] }
}

grammar Attributes {
    regex attributeDescription { <attributeType> <options> }
    regex attributeType { <oid> }
    regex oid { <Common::descr> | <Common::numericoid> }
    token options { [ ';' <option> ]*? }
    token option { <[- \x41..\x5A \x61..\x7A \x30..\x39]> } # -A..Za..z0..9
}

# Common regexes
grammar Search {
    token TOP { <filter> }
    token filter { '(' <filtercomp> ')'}
    token filtercomp { <and> | <or> | <not> | <search-item> }
    token and { '&' <filterlist> }
    token or { '|' <filterlist> }
    token not { '!' <filterlist> }
    token filterlist { <filter>+ }
    token search-item { <simple> | <present> | <substring> | <extensible> }
    regex simple { <attr> <filtertype> <assertionValue> }
    token filtertype { "=" | "~=" | "<=" | ">=" }
    token extensible { [ <attr> <dnattrs>? <matching-rule>? ':=' <assertionValue> ] | [ <dnattrs>? <matching-rule> ':=' <assertionValue> ] }
    token present { <attr> '=*' }
    token substring { <attr> '=' <initial>? <any> <final>? }
    token initial { <assertionValue> }
    token any { '*' [<assertionValue> '*']*? }
    token final { <assertionValue> }
    regex attr { <Attributes::attributeDescription> }
    token dnattrs { ':dn' }
    token matching-rule { ':' <Attributes::oid> }
    token assertionValue { [ <normal> | <escaped> ]* }
    token normal { <UTF1SUBSET> | <Common::UTFMB> }
    token escaped { "\\" <Common::hex> <Common::hex> }
    token UTF1SUBSET { <[\x01..\x27 \x2B..\x5B \x5D..\x7F]> }
}

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
                    ["?" <Search::filter>?
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
            with $<query><Search::filter> {
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