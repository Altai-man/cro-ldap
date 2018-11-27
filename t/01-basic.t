use Cro::LDAP::Client;
use Cro::LDAP::Server;
use Cro::LDAP::Request;
use Cro::LDAP::Response;
use LDAP::Mock;
use Test;

plan *;

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :20000port);
$server.start;
QUIT {
    $server.stop;
}

my $client = Cro::LDAP::Client.new;

await $client.connect('localhost', 20000);
# "Foo" name, simple authentication used
given await $client.bind("Foo") -> $resp {
    ok $resp ~~ Cro::LDAP::Response::Bind, 'Got Response::Bind object';
}

done-testing;
