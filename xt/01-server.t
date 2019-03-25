use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Worker;
use Test;

plan *;

constant $port = 2000;

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        return BindResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }

    method unbind($req) {
    }

    method search($req) {
        supply {
            emit (searchResEntry => SearchResultEntry.new(object-name => "foo",
                    attributes => Array[PartialAttributeListBottom].new(
                            PartialAttributeListBottom.new(type => "first", vals => ASNSetOf[ASN::Types::OctetString].new("Epsilon", "Solution")),
                            PartialAttributeListBottom.new(type => "second", vals => ASNSetOf[ASN::Types::OctetString].new("Gamma", "Narberal"))
                    )));
            emit (searchResDone => SearchResultDone.new(
                    result-code => success,
                    matched-dn => "",
                    error-message => ""));
        }
    }
}

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :$port);

$server.start;
END { $server.stop }

my @args = <ldapsearch -H ldap://localhost:2000/ -x -b "o=it-sudparis,c=eu" -D "cn=manager,o=it,c=eu" -w secret>;
my $proc = Proc::Async.new(|@args);

my $search-res = Promise.new;
my $search-num = Promise.new;
my $search-object = Promise.new;

react {
    whenever $proc.stdout {
        $search-res.keep if $_ ~~ /'result: 0 Success'/;
        $search-num.keep if $_ ~~ /'search: 2'/;
        $search-object.keep if $_ ~~ /'first: Epsilon'/ && $_ ~~ /'second: Narberal'/;
    }
    whenever $proc.start {
        done
    }
}

await Promise.allof($search-res, $search-num, $search-object);

is $search-res.status, Kept, "Success code";
is $search-num.status, Kept, "Correct number of results";
is $search-object.status, Kept, "Attributes";

done-testing;
