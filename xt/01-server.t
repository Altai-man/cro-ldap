use ASN::Types;
use Cro::LDAP::Types;
use Cro::LDAP::Server;
use Cro::LDAP::Worker;
use Test;

plan *;

constant $port = 2000;



sub test-command($command, :@args, :@checks) {
    my @base = <-H ldap://localhost:2000/ -x -D "cn=manager,o=it,c=eu" -w secret>;
    my $proc = Proc::Async.new($command, |@base, |@args);
    my $output = "";

    react {
        whenever $proc.stdout {
            $output ~= $_;
        }
        whenever $proc.start {
            done;
        }

        # Timeout
        whenever Promise.in(5) {
            done;
        }
    }

    for @checks -> $check {
        subtest {
            ok $check($output);
        }, "Test $command";
    }
}

class MockLDAPWorker does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        return BindResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }

    method unbind($req) {
    }

    method add($req) {
        return AddResponse.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
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
END $server.stop;

my $proc;
my @args = <-H ldap://localhost:2000/ -x -D "cn=manager,o=it,c=eu" -w secret>;

test-command("ldapsearch",
        args => <-b o=it-sudparis,c=eu>,
        checks => [* ~~ /'result: 0 Success'/,
        * ~~ /'search: 2'/,
        * ~~ /'first: Epsilon'/,
        * ~~ /'second: Narberal'/]);

test-command("ldapadd",
        args => <-f xt/input-files/add.ldif>,
        checks => [* ~~ /'adding new entry "uid=jsmith,ou=people,dc=example,dc=com'/]);

done-testing;
