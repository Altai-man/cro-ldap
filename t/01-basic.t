use Cro::LDAP::Client;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Cro::LDAP::Worker;
use Test;

plan *;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        return BindResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }
}

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
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
}

done-testing;
