# Cro::LDAP::Entry

The `Cro::LDAP::Entry` class represents a single entry returned from
Search operation.

It has attribute `$.dn` of type `Str` that represents this entry
distinguished name and `%.attributes` hash of its attributes.

`Cro::LDAP::Entry` implements `Associative` role, using its attributes
as keys and values, so values can be retrieved directly without
accessing `%.attributes` attribute.

```perl6
my $entry = Cro::LDAP::Entry.new(
    dn => 'uid=john.doe,ou=People,dc=example,dc=com',
    attributes => {
        name => 'John',
        age => '15',
        nicknames => ('Johnny', 'Foo')
    }
);
say $entry.dn;    # uid=john.doe,ou=People,dc=example,dc=com
say $entry.attributes<name>; # John
# or
say $entry<name>; # John
```
