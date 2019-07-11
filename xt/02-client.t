use Cro::LDAP::Client;
use Test;

# TEST PLAN

# Add your OpenLDAP server IP to hosts file under `ldaps.test.local`
my $ldap = await Cro::LDAP::Client.connect("ldap://ldaps.test.local");

my $resp = await $ldap.bind(name => "uid=cro,ou=people,dc=test,dc=local", password => "pcro");

my $search-resp = $ldap.search(:dn<ou=people,dc=test,dc=local>, :filter<objectclass=*>);

react {
    whenever $search-resp -> $entry {
        note $entry.dn;
        for $entry.attributes.kv -> $k, $v {
            my $value-str = $v ~~ Blob ?? $v.decode !! $v.map(*.decode);
            note "$k -> $value-str";
        }
    }
    CLOSE {
        note "Closing...";
    }
}

# TODO

# add

# modify

# modifyDN

# delete

# compare

done-testing;
