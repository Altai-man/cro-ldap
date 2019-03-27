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

# delete

# compare

# ModDN

# Modify

done-testing;
