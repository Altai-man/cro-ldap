# Cro::LDAP::Reference

The `Cro::LDAP::Reference` class represents a single set of references
returned from Search operation.

It has a single attribute `@.refs`, which is a `Positional` of strings
that represents server's referrals.

`Cro::LDAP::Reference` implements `Positional` and `Iterable` roles,
which makes it possible to work with it as with normal `Positional`,
while preserving ability to smartmatch against its type.

```perl6
my $refs = Cro::LDAP::Reference.new(
    refs => (
       "ldap://hostb/OU=People,DC=Example,DC=NET??sub",
       "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub"
    )
);

.say for $refs; # iterates internal references

say $refs[1]; # ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub
```
