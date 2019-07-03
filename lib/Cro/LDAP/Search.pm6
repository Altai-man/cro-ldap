use Cro::LDAP::Types;
use Cro::LDAP::Grammars;

grammar Cro::LDAP::Search::Grammar {
    regex TOP { <filter> }
    regex filter { '(' <filtercomp> ')'}
    regex filtercomp { <and> | <or> | <not> | <search-item> }
    regex and { '&' <filterlist> }
    regex or { '|' <filterlist> }
    regex not { '!' <filter> }
    regex filterlist { <filter>+ }
    regex search-item { <simple> | <present> | <substring> | <extensible> }
    regex simple { <attr> <filtertype> <assertionValue> }
    regex filtertype { "=" | "~=" | "<=" | ">=" }
    regex extensible {
        | [ <attr> <dnattrs>? <matching-rule>? ':=' <assertionValue> ]
        | [ <dnattrs>? <matching-rule> ':=' <assertionValue> ] }
    regex present { <attr> '=*' }
    regex substring { <attr> '=' <initial>? <any> <final>? }
    regex initial { <assertionValue> }
    regex any { '*' [<assertionValue> '*']*? }
    regex final { <assertionValue> }
    regex attr { <Attributes::attributeDescription> }
    regex dnattrs { :i ':dn' }
    regex matching-rule { ':' <Attributes::oid> }
    regex assertionValue { [ <normal> | <escaped> ]* }
    regex normal { <UTF1SUBSET> | <Common::UTFMB> }
    regex escaped { "\\" <Common::hex> <Common::hex> }
    regex UTF1SUBSET { <[\x01..\x27 \x2B..\x5B \x5D..\x7F]> }
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
                attribute-desc => $<attr>.made,
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

    method substring($/) {
        make (substrings => SubstringFilter.new(
                type => $<attr>.made,
                substrings => ASNSequenceOf[SubstringsBottom].new(seq => [
                    |(SubstringsBottom.new((initial => ASN::Types::OctetString.new(~$_))) with $<initial>),
                    |$<any>.made,
                    |(SubstringsBottom.new((final => ASN::Types::OctetString.new(~$_))) with $<final>)])
                ));
    }

    method any($/) {
        my @results;
        for @($<assertionValue>) -> $item {
            @results.push: SubstringsBottom.new((any => ASN::Types::OctetString.new(~$item)));
        }
        if @results.elems {
            make ASNSequenceOf[SubstringsBottom].new(seq => @results);
        } else {
            make ();
        }
    }

    method attr($/) { make ~$/ }

    method extensible($/) {
        my %opts;
        with $<dnattrs> {
            %opts<dn-attributes> = True;
        }
        with $<attr> {
            %opts<type> = ~$_;
        }
        with $<matching-rule> {
            %opts<matching-rule> = $_.made;
        }
        with $<assertionValue> {
            %opts<match-value> = $_.made;
        }

        my $assertion = MatchingRuleAssertion.new(|%opts);
        make (extensibleMatch => $assertion)
    }

    method present($/) {
        make (present => ASN::Types::OctetString.new($<attr>.made));
    }

    method matching-rule($/) {
        make ~$<Attributes::oid>;
    }

    method assertionValue($/) {
        make ~$/;
    }
}

class Cro::LDAP::Search {
    method parse(Str $filter-pattern) {
        Cro::LDAP::Search::Grammar.parse(
                $filter-pattern,
                actions => Cro::LDAP::Search::Actions).made;
    }
}
