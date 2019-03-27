use Cro::LDAP::Test::MockServer;
use Cro::LDAP::Types;
use Cro::LDAP::Server;
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

    subtest {
        for @checks -> $check {
            ok $check($output);
        }
    }, "Test $command";
}

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new,
        :host('localhost'),
        :$port);

$server.start;
END $server.stop;

my @args = <-H ldap://localhost:2000/ -x -D "cn=manager,o=it,c=eu" -w secret>;

test-command("ldapadd",
        args => <-f xt/input-files/add.ldif>,
        checks => [* ~~ /'adding new entry "uid=jsmith,ou=people,dc=example,dc=com'/]);

test-command("ldapdelete",
        args => <"cn=Robert Jenkins,ou=People,dc=example,dc=com">,
        checks => [*.chars == 0]);

# compare
test-command("ldapcompare",
        args => <uid=bjensen,ou=people,dc=example,dc=com sn:smith>,
        checks => [* eq "TRUE\n"]);

test-command("ldapmodrdn",
        args => ["-r", "-s", "cn=Robert Jenkins,ou=People,dc=example,dc=com", "cn=Modify Me, o=University of Life, c=US", "cn=The New Me"],
        checks => [* eq ""]);

# Modify

test-command("ldapsearch",
        args => <-b o=it-sudparis,c=eu>,
        checks => [* ~~ /'result: 0 Success'/,
        * ~~ /'search: 2'/,
        * ~~ /'first: Epsilon'/,
        * ~~ /'second: Narberal'/]);

# Ext

done-testing;
