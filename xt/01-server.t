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
    method success-result($type) {
        return $type.new(
                result-code => success,
                matched-dn => "",
                error-message => "");
    }

    method bind($req --> BindResponse) {
        self.success-result(BindResponse);
    }

    method unbind($req) {}

    method add($req) {
        self.success-result(AddResponse);
    }

    method delete($req) {
        self.success-result(DelResponse);
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

test-command("ldapdelete",
        args => <"cn=Robert Jenkins,ou=People,dc=example,dc=com">,
        checks => [*.chars == 0]);

done-testing;
