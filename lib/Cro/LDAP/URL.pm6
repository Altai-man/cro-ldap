use Cro::Uri;
use Cro::LDAP::DN;
use Cro::LDAP::Grammars;
use Cro::LDAP::Search;

# Common regexes

class Cro::LDAP::URL {
    has Str $.hostname;
    has Bool $.is-secure;
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
            "/" [ <Cro::LDAP::DN::Grammar::relativeDN>* % ',' ] [ "?" <attributes>?
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

        token prefix { :i 'ldap' 's'? '://' }
    }

    class Actions {
        method TOP($/) {
            my $is-secure = $<prefix> eq 'ldaps://';

            my ($scope, $filter, @attributes, @DN, @extensions) = ('base', 'objectClass=*');
            my $host = ~$<entity><host>;
            my $port = $<entity><port>;
            with $<query><Cro::LDAP::DN::Grammar::relativeDN> {
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
                    :$is-secure,
                    hostname => $host.chars ?? $host !! Str,
                    port => $port ?? $port.Int !! Int, :@DN, :@attributes,
                    :$scope, :$filter, :@extensions;
        }
    }

    method parse(Str $url) {
        Grammar.parse($url, :actions(Actions)).made;
    }
}