use Cro::LDAP::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Worker;
use Test;

plan *;

# ldapsearch -d 1 -H ldap://localhost:2000/ -x -b "o=it-sudparis,c=eu" -D "cn=manager,o=it,c=eu" -w secret
constant $port = 2000;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        return BindResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }

    method search($req --> SearchResponse) {
        note $req;
        die;
    }
}

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :$port);
$server.start;
say "Started the server on port $port";

react whenever signal(SIGINT) {
    say "Closing...";
    $server.stop;
    exit;
}

done-testing;
