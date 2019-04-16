use Cro::LDAP::Types;
use Cro::LDAP::Grammars;

grammar Cro::LDAP::Search::Grammar {
    token TOP { <filter> }
    token filter { '(' <filtercomp> ')'}
    token filtercomp { <and> | <or> | <not> | <search-item> }
    token and { '&' <filterlist> }
    token or { '|' <filterlist> }
    token not { '!' <filter> }
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

class Cro::LDAP::Search::Actions {
    method TOP($/) { make $<filter>.made }
    method filter($/) { make $<filtercomp>.made }
    method filtercomp($/) {
        with $<and> {
            make Filter.new((and => $_.made));
        }
        orwith $<or> {
            make Filter.new((or => $_.made));
        }
        orwith $<not> {
            make Filter.new((not => $_.made));
        }
        orwith $<search-item> {
            make Filter.new((.made));
        }
    }

    method and($/) { make $<filterlist>.made }
    method or($/) { make $<filterlist>.made }
    method not($/) { make $<filter>.made }

    method filterlist($/) {
        my @items;
        for $<filter> {
            @items.push: .made;
        }
        make ASNSetOf[Filter].new(|@items);
    }

    method search-item($/) {
        with $<simple> { make .made }
        orwith $<present> { make .made }
        orwith $<substring> { make .made }
        orwith $<extensible> { make .made }
    }

    method simple($/) {
        my $value = AttributeValueAssertion.new(
                attribute-desc => ~$<attr>,
                assertion-value => ~$<assertionValue>);
        given $<filtertype> {
            when "=" {
                make (equalityMatch => $value);
            }
            when "~=" {
                make (approxMatch => $value);
            }
            when "<=" {
                make (lessOrEqual => $value);
            }
            when ">=" {
                make (greaterOrEqual => $value);
            }
        }
    }
}

class Cro::LDAP::Search {
    method parse(Str $filter-pattern) {
        Cro::LDAP::Search::Grammar.parse(
                $filter-pattern,
                actions => Cro::LDAP::Search::Actions).made;
    }
}
