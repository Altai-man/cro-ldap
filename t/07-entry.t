use Test;
use Cro::LDAP::Entry;

plan 3;

my $entry = Cro::LDAP::Entry.new(
    dn => 'uid=john.doe,ou=People,dc=example,dc=com',
    attributes => {
        name => 'John',
        age => '15',
        nicknames => ('Johnny', 'Foo')
    }
);
is $entry.dn, 'uid=john.doe,ou=People,dc=example,dc=com', 'Entry DN is correct';
is $entry.attributes<name>, 'John', 'Entry name attribute is correct (direct)';
is $entry<name>, 'John', 'Entry name attribute is correct (indirect)';
