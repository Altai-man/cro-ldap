use Cro::LDAP::Test::MockServer;
use Cro::LDAP::Client;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Test;

plan *;

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :20000port);
$server.start;
END $server.stop;

my $client = Cro::LDAP::Client.new;

await $client.connect('localhost', 20000);

given await $client.bind("cn=manager,o=it,c=eu", auth => "secret") -> $resp {
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
}

given await $client.add("uid=jsmith,ou=people,dc=example,dc=com",
        ["objectclass" => "inetOrgPerson", "objectclass" => "person"]) -> $resp {
    ok $resp ~~ AddResponse, 'Got Response::Add object';
}

given await $client.delete("cn=Robert Jenkins,ou=People,dc=example,dc=com") -> $resp {
    ok $resp ~~ DelResponse, 'Got Response::Del object';
}

given await $client.compare(
        "uid=bjensen,ou=people,dc=example,dc=com",
        ava => AttributeValueAssertion.new(
                attribute-desc => "sn",
                assertion-value => "smith"
                )) -> $resp {
    ok $resp ~~ CompareResponse, 'Got Response::Compare object';
    is $resp.result-code, compareTrue, 'Correct response code';
}

my @changes = add => { :type<cn>, :vals(['test']) },
    replace => { :type<cp>, :vals(['test1', 'test2']) },
    delete => { :type<ck> };
given await $client.modify("cn=modify", @changes) -> $resp {
    ok $resp ~~ ModifyResponse, 'Got Response::Modify object';
}

given await $client.modifyDN(
        dn => "cn=Modify Me, o=University of Life, c=US",
        new-dn => "cn=The New Me",
        :delete,
        new-superior => "cn=Robert Jenkins,ou=People,dc=example,dc=com") -> $resp {
    ok $resp ~~ ModifyDNResponse, 'Got Response::ModDN object';
}

react {
    whenever $client.search(base => "c=US", filter => '(&(sn=Barr)(o=Texas Instruments))') -> $entry {
        ok $entry ~~ SearchResultEntry, "Received a result entry";
    }
}

done-testing;
