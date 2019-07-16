use Test;
use Cro::LDAP::Entry;

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

my $ldif = q:to/END/;
version: 1
# Add a new entry
dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com
changetype: add
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Fiona Jensen
sn: Jensen
uid: fiona
telephonenumber: +1 408 555 1212
jpegphoto:< file://t/testdata/test.jpg

# Delete an existing entry
dn: cn=Robert Jensen, ou=Marketing, dc=airius, dc=com
changetype: delete

# Modify an entry’s relative distinguished name
dn: cn=Paul Jensen, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: cn=Paula Jensen
deleteoldrdn: 1

# Rename an entry and move all of its children to a new location in
# the directory tree (only implemented by LDAPv3 servers).
dn: ou=PD Accountants, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: ou=Product Development Accountants
deleteoldrdn: 0
newsuperior: ou=Accounting, dc=airius, dc=com

# Modify an entry: add an additional value to the postaladdress
# attribute, completely delete the description attribute, replace
# the telephonenumber attribute with two values, and delete a specific
# value from the facsimiletelephonenumber attribute
dn: cn=Paula Jensen, ou=Product Development, dc=airius, dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

# Modify an entry: replace the postaladdress attribute with an empty
# set of values (which will cause the attribute to be removed), and
# delete the entire description attribute. Note that the first will
# always succeed, while the second will only succeed if at least
# one value for the description attribute is present.
dn: cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com
changetype: modify
replace: postaladdress
-
delete: description
-
END

my @entries = Cro::LDAP::Entry.parse($ldif);

subtest {
    $entry = @entries[0];
    is $entry.dn, "cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-add, 'Correct operation';
    is $entry<cn>, 'Fiona Jensen';
    ok $entry<jpegphoto> ~~ Buf;
    is $entry<jpegphoto>.elems, 1229;
    is $entry<objectclass>.elems, 3;
}, 'First entry';

subtest {
    $entry = @entries[1];
    is $entry.dn, "cn=Robert Jensen, ou=Marketing, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-delete, 'Correct operation';
    is $entry.attributes.elems, 0;
}, 'Second entry';

subtest {
    $entry = @entries[2];
    is $entry.dn, "cn=Paul Jensen, ou=Product Development, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-moddn, 'Correct operation';
    ok $entry<delete-on-rdn>;
    is $entry<newrdn>, 'cn=Paula Jensen';
    nok $entry<newsuperior>;
}, 'Third entry';

subtest {
    $entry = @entries[3];
    is $entry.dn, "ou=PD Accountants, ou=Product Development, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-moddn, 'Correct operation';
    nok $entry<delete-on-rdn>;
    is $entry<newrdn>, 'ou=Product Development Accountants';
    nok $entry<newsuperior>;
}, 'Fourth entry';

subtest {
    $entry = @entries[4];
    is $entry.dn, "cn=Paula Jensen, ou=Product Development, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-modify, 'Correct operation';
    is $entry<add>, [postaladdress => '123 Anystreet $ Sunnyvale, CA $ 94086'];
    is $entry<delete>, ['description', :facsimiletelephonenumber("+1 408 555 9876")];
    is $entry<replace>, [telephonenumber => ['+1 408 555 1234', '+1 408 555 5678']]
}, 'Fifth entry';

subtest {
    $entry = @entries[5];
    is $entry.dn, "cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com", 'Correct DN';
    is $entry.operation, LDIF::Operation::ldif-modify, 'Correct operation';
    is $entry<delete>, <description>;
    is $entry<replace>, <postaladdress>;
}, 'Sixth entry';

done-testing;