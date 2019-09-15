use Test;
use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
use Cro::LDAP::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Client;

plan 3;

my %tls = private-key-file => 't/fake-keys/server-key.pem',
          certificate-file => 't/fake-keys/server-crt.pem';

my Cro::Service $server = Cro::LDAP::Server.new(
        worker => MockLDAPWorker.new,
        :host('localhost'),
        :3894port, :%tls);
$server.start;

END $server.stop;

my $ca-file = 't/fake-keys/ca-crt.pem';

throws-like {
    await Cro::LDAP::Client.connect("ldaps://localhost:3894");
}, X::Cro::LDAP::Client::NoCAFileForSecureConnection, "Attempt to use ldaps without CA file throws an exception";

my $client = await Cro::LDAP::Client.connect("ldaps://localhost:3894", :$ca-file);

given $client.bind(name => "dc=org,dc=com", password => "mysecret") -> $resp {
    is $resp.result-code, success, "Got correct bind code";
}

my $p = Promise.new;

react {
    whenever $client.search(dn => "dc=org,dc=com", filter => "cn=hackers") {
        when Cro::LDAP::Entry {
            $p.keep if $_.dn eq "foo";
        }
    }
}

await Promise.anyof($p, Promise.in(5));
pass "Correct dummy DN" if $p.status ~~ Kept;

$client.disconnect;
