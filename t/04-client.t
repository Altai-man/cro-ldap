use ASN::Types;
use Cro::LDAP::Client;
use Cro::LDAP::Worker;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Test;

plan *;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        is $req.name, "cn=manager,o=it,c=eu", "Bind DN is correct";
        is $req.authentication.value.value, "secret", "Password is correct";

        return BindResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }
    method unbind($req) {}

    method search($req) {
        emit (searchResDone => SearchResultDone.new(
                result-code => success,
                matched-dn => "",
                error-message => ""));
    }
}

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

done-testing;
