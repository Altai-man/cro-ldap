use Test;
use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
use Cro::LDAP::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Client;

plan 2;

my %tls = private-key-file => 't/fake-keys/server-key.pem',
          certificate-file => 't/fake-keys/server-crt.pem';

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :3894port, :%tls);
$server.start;

END $server.stop;

my $ca-file = 't/fake-keys/ca-crt.pem';

my $client = await Cro::LDAP::Client.connect("ldaps://localhost:3894", :$ca-file);

given await $client.bind(name => "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com", password => "mysecret") -> $resp {
    is $resp.result-code, success, "Got correct bind code";
}

react {
    whenever $client.search(dn => "dc=glauth,dc=com", filter => "cn=hackers") -> $res {
        is $res.dn, "foo", "Correct dummy DN";
    }
}

$client.disconnect;
