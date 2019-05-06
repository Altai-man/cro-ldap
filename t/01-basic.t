use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
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

await $client.connect(:host<localhost>, :port(20000));
# "Foo" name, simple authentication used
given await $client.bind(name => "Foo") -> $resp {
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
}

done-testing;
