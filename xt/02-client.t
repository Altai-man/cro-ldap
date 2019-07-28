use Cro::LDAP::Extension;
use Cro::LDAP::Client;
use Cro::LDAP::Types;
use Test;

# Add your OpenLDAP server IP to hosts file under `ldaps.test.local`
# Its hostname is defined as `ldaps.test.local`, root dc is `test.local`
# user `uid=cro,ou=people,dc=test,dc=local` with password `pcro` must exist
# admin `cn=admin,dc=test,dc=local` with password `psecret must exist

my Cro::LDAP::Client $ldap = await Cro::LDAP::Client.connect("ldap://ldaps.test.local");

my $bind-resp = $ldap.bind(name => "uid=cro,ou=people,dc=test,dc=local", password => "pcro");
is $bind-resp.result-code, success, 'Could bind';

my $search-resp = $ldap.search(:dn<ou=people,dc=test,dc=local>, :filter<objectclass=*>);

my $closed-p = Promise.new;

react {
    whenever $search-resp -> $entry {
        is $entry.dn, 'ou=people,dc=test,dc=local'|'uid=cro,ou=people,dc=test,dc=local', 'Correct DN';
        for $entry.attributes.kv -> $k, $v {
            my $value-str = $v ~~ Blob ?? $v.decode !! $v.map(*.decode);
            if $k eq 'uid' {
                is $value-str, 'cro', 'UID is correct';
            }
        }
    }
    CLOSE {
        $closed-p.keep;
    }
}

await Promise.anyof($closed-p, Promise.in(10));

is $closed-p.status, Kept, 'Search supply was closed';

is (await $ldap.extend(Cro::LDAP::Extension::WhoAmI.new)), 'dn:uid=cro,ou=people,dc=test,dc=local', 'WHOAMI extended works';

is $ldap.extend("1.3.6.1.4.1.4203.1.11.3").result.response.decode, 'dn:uid=cro,ou=people,dc=test,dc=local', 'WHOAMI manual works';

$bind-resp = $ldap.bind(name => "cn=admin,dc=test,dc=local", password => "psecret");
is $bind-resp.result-code, success, 'Could re-bind';

my @entries = Cro::LDAP::Entry.parse(slurp 'xt/input-files/cro-add.ldif');

for @entries -> $entry {
    note $entry;
    my $res = await $ldap.sync($entry);
    note $res;
}

my $modDN-resp = await $ldap.modifyDN(:dn<uid=test,ou=people,dc=test,dc=local>, new-dn => "uid=tester");
is $modDN-resp.result-code, success, 'Could rename';

my @changes = replace => [:givenName['Robot']];
my $modify-resp = await $ldap.modify("uid=tester,ou=people,dc=test,dc=local", @changes);
is $modify-resp.result-code, success, 'Could modify givenName';

my $cmp-resp = await $ldap.compare("uid=tester,ou=people,dc=test,dc=local", "sn", 'Tester');
is $cmp-resp.result-code, compareTrue, 'Compared as true';

my $del-resp = await $ldap.delete("uid=tester,ou=people,dc=test,dc=local");
is $del-resp.result-code, success, 'Could delete';

$del-resp = await $ldap.delete("cn=test,ou=groups,dc=test,dc=local");
is $del-resp.result-code, success, 'Could delete 2';

$ldap.unbind;

done-testing;
