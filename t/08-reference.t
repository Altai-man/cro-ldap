use Test;
use Cro::LDAP::Reference;

plan 4;

my $refs := Cro::LDAP::Reference.new(
    refs => (
        "ldap://hostb/OU=People,DC=Example,DC=NET??sub",
        "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub"
    )
);

my @data = "ldap://hostb/OU=People,DC=Example,DC=NET??sub",
            "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub";

my $i = 0;
for $refs {
    is $_, @data[$i], "Iterator on bind works";
    $i++;
}

is $refs[1], 'ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub', 'Positional role is implemented (1)';
is $refs.elems, 2, 'Positional role is implemented (2)';

done-testing;
