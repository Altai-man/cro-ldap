use Test;
use Cro::LDAP::Types;
use Cro::LDAP::Search;

sub parses($desc, $pattern, *@checks) {
    with try Cro::LDAP::Search.parse($pattern) -> $parsed {
        subtest {
            for @checks.kv -> $i, $check {
                ok $check($parsed), "Check {$i + 1}";
            }
        }, $desc;
    }
    else {
        diag "LDAP Search Filter string parsing failed";
        flunk $desc;
        skip "Failed to parse", @checks.elems;
    }
}

parses "pattern 1", '(cn=Babs Jensen)',
    -> $_ { .ASN-value eqv Pair.new('equalityMatch', AttributeValueAssertion.new(attribute-desc => "cn", assertion-value => "Babs Jensen")) };

parses "pattern 2", '(!(cn=Tim Howes))',
    -> $_ { .ASN-value eqv :not(Filter.new((:equalityMatch(AttributeValueAssertion.new(attribute-desc => "cn", assertion-value => "Tim Howes"))))) };

parses "pattern 3", '(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))';

parses "pattern 4", '(o=univ*of*mich*)';

parses "pattern 5", '(seeAlso=)';

parses "pattern 6", '(cn:caseExactMatch:=Fred Flintstone)';

parses "pattern 7", '(cn:=Betty Rubble)';

parses "pattern 8", '(sn:dn:2.4.6.8.10:=Barney Rubble)';

parses "pattern 9", '(o:dn:=Ace Industry)';

parses "pattern 10", '(:1.2.3:=Wilma Flintstone)';

parses "pattern 11", '(:DN:2.4.6.8.10:=Dino)';

parses "pattern 12", '(objectclass=*)';

parses "pattern custom", '(cn=ab*def*mno*stu*yz)';

done-testing;
