use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
use Cro::LDAP::Client;
use Cro::LDAP::Entry;
use Cro::LDAP::Reference;
use Cro::LDAP::Schema;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Test;

plan *;

is Cro::LDAP::Client.new.host, "localhost", "Default host is localhost";

is Cro::LDAP::Client.new.port, 389, "Default port is 389";

# Connection
sub prepare-server($host = 'localhost', $port = 3890) {
    my Cro::Service $server = Cro::LDAP::Server.new(
            server => MockLDAPWorker.new,
            :$host, :$port);
    $server.start;
    $server;
}

{
    my $conn = Cro::LDAP::Client.new.connect(:host<localhost>, :port(3891));
    ok $conn ~~ Promise, "connect method returns a Promise";
    todo "Abilities are overestimated", 1;
    dies-ok { await $conn }, "Connection dies";
#    ok $conn.status ~~ Broken, "connect Promise is broken if no server available";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;

    lives-ok {
        my $client = Cro::LDAP::Client.new;
        my $conn = await $client.connect(:host<localhost>, :port(3890));
        ok $conn ~~ Cro::LDAP::Client:D, "connect method resolves into caller Cro::LDAP::Client";
    }, "Can connect to a working server";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;
    lives-ok {
        await Cro::LDAP::Client.new(:host<localhost>, :port(3890)).connect;
    }, "Argument-less connect takes data from instance";
    subtest {
        lives-ok {
            ok (await Cro::LDAP::Client.connect(:host<localhost>, :port(3890))) ~~ Cro::LDAP::Client:D;
        }
    }, "connect can be called on Cro::LDAP::Client type object";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;
    lives-ok {
        await Cro::LDAP::Client.connect("ldap://localhost:3890/");
    }, "Can connect using canonical LDAP URL";
    lives-ok {
        await Cro::LDAP::Client.new(port => 3890).connect("ldap:///");
    }, "Can connect using empty canonical ldap url";
    lives-ok {
        await Cro::LDAP::Client.new(:host<foo>, :port(15)).connect("ldap://localhost:3890/");
    }, "connect LDAP URL overrides per-instance values";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;
    lives-ok {
        my $client = await Cro::LDAP::Client.connect("ldap://localhost:3890/");
        $client.disconnect;
    }, "Client can disconnect";
    throws-like {
        my $client = await Cro::LDAP::Client.connect("ldap://localhost:3890/");
        $client.connect("ldap://localhost:3890/");
    }, X::Cro::LDAP::Client::DoubleConnect, message => /'attempt to connect'/;
    lives-ok {
        my $client = await Cro::LDAP::Client.connect("ldap://localhost:3890/");
        $client.disconnect;
        $client.connect(port => 3890);
    }, "Can connect after disconnection";
}

# Operations

throws-like { Cro::LDAP::Client.bind }, X::Cro::LDAP::Client::NotConnected,
        message => /'bind'/, "Cannot bind when no connection";
throws-like { Cro::LDAP::Client.unbind }, X::Cro::LDAP::Client::NotConnected,
        message => /'unbind'/, "Cannot unbind when no connection";
throws-like { Cro::LDAP::Client.search(:dn<a>, :filter<()>) }, X::Cro::LDAP::Client::NotConnected,
        message => /'search'/, "Cannot search when no connection";
throws-like { Cro::LDAP::Client.modify("", ()) }, X::Cro::LDAP::Client::NotConnected,
        message => /'modify'/, "Cannot modify when no connection";
throws-like { Cro::LDAP::Client.add("cn=add") }, X::Cro::LDAP::Client::NotConnected,
        message => /'add'/, "Cannot add when no connection";
throws-like { Cro::LDAP::Client.delete("cn=delete") }, X::Cro::LDAP::Client::NotConnected,
        message => /'delete'/, "Cannot delete when no connection";
throws-like { Cro::LDAP::Client.modifyDN(dn => "", new-dn => "") }, X::Cro::LDAP::Client::NotConnected,
        message => /'modify DN'/, "Cannot modify DN when no connection";
throws-like { Cro::LDAP::Client.compare("cn=cmp", "a", "b") }, X::Cro::LDAP::Client::NotConnected,
        message => /'compare'/, "Cannot compare when no connection";
#throws-like { Cro::LDAP::Client.extend(Int) }, X::Cro::LDAP::Client::NotConnected,
#        message => /'extended'/, "Cannot send Extended Request when no connection";

# Checkers for unusual operations

my $unbind-p = Promise.new;
my $abandon-promise-p = Promise.new;
my $abandon-supply-p = Promise.new;

my @CHECKS = [
    (* ~~ UnbindRequest, $unbind-p),
    (* ~~ 14, $abandon-promise-p),
    (* ~~ 16, $abandon-supply-p)
];

my Cro::Service $server = Cro::LDAP::Server.new(
        server => MockLDAPWorker.new(:@CHECKS),
        :host('localhost'),
        :20000port);
$server.start;
END $server.stop;

my $client = await Cro::LDAP::Client.connect('ldap://localhost:20000/');

# BIND
subtest {
    my $resp;

    $resp = await $client.bind;
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Anonymous bind", "Recognized as anonymous bind";

    $resp = await $client.bind(name => "cn=manager,o=it,c=eu");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Unauthenticated bind", "Recognized as unauthenticated bind";

    $resp = await $client.bind(name => "cn=manager,o=it,c=eu", password => "secret");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Normal bind", "Recognized as name/password bind";
    is $resp.server-sasl-creds.decode, "CustomCreds", "SASL server creds were received";

    $resp = await $client.bind(name => "dn=no-more");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, busy, "Returned correct result code";
}, "Bind request-response";

#subtest {
#    $client.unbind;
#    await Promise.anyof(Promise.in(5), $unbind-p);
#    is $unbind-p.status, Kept, "Unbind request was sent";
#}, "Unbind request";

# SEARCH
subtest {
    my $single-resp = $client.search(:dn<o=myhost>, :filter<cn=root>);
    ok $single-resp ~~ Supply, "Search operation returns a Supply";
    react {
        whenever $single-resp -> $entry {
            is $entry.dn, "foo", "DN is preserved";
            is-deeply $entry<first>.map(*.decode).sort, <Epsilon Solution>.sort, "First attr is preserved";
            is-deeply $entry<second>.map(*.decode).sort, <Gamma Narberal>.sort, "Second attr is preserved";

            LAST {
                pass "Closed the supply";
            }
        }
    }
    my $many-resp = $client.search(:dn<o=myhost>, :filter<objectclass=*>);
    my $number-of-responses = 0;
    my $number-of-refs = 0;
    react {
        whenever $many-resp.grep(* ~~ Cro::LDAP::Entry) -> $entry {
            $number-of-responses++;
        }
        whenever $many-resp.grep(* ~~ Cro::LDAP::Reference) -> $ref {
            $number-of-refs++;
        }
    }
    is $number-of-responses, 10, "Got 10 responses";
    is $number-of-refs, 0, "Got 0 references";

    my $many-resp-with-refs = $client.search(:dn<o=myhost>, :filter<foo=b*r>);
    react {
        whenever $many-resp-with-refs.grep(* ~~ Cro::LDAP::Entry) -> $entry {
            $number-of-responses++;
        }
        whenever $many-resp-with-refs.grep(* ~~ Cro::LDAP::Reference) -> $ref {
            $number-of-refs++;
        }
    }
    is $number-of-responses, 20, "Got 20 responses";
    is $number-of-refs, 5, "Got 5 references";

}, "Search request";

# MODIFY
subtest {
    my $modify-resp = await $client.modify("cn=modify1", add => { :type<name>, :vals<Tester> });
    ok $modify-resp ~~ ModifyResponse, "Got ModifyResponse object";
    is $modify-resp.matched-dn.decode, "cn=modify1", "Got correct DN";
    is $modify-resp.error-message.decode, "addnameTester", "Sent correct change";

    my @changes = add => { :type<cn>, :vals(['test']) },
            replace => { :type<cp>, :vals(['test1', 'test2']) },
            delete => { :type<ck> };
    $modify-resp = await $client.modify("cn=modify15", @changes);
    ok $modify-resp ~~ ModifyResponse, "Got ModifyResponse object";
    is $modify-resp.matched-dn.decode, "cn=modify15", "Got correct DN";
    ok $modify-resp.error-message.decode ~~ "addcntestreplacecptest1 test2deleteck" ||
       $modify-resp.error-message.decode ~~ "addcntestreplacecptest2 test1deleteck", "Sent correct change set";
}, "Modify request";

# ADD
subtest {
    my $resp = await $client.add("uid=jsmith,ou=people,dc=example,dc=com",
            attrs => ["objectclass" => "inetOrgPerson", "objectclass" => "person"]);
    ok $resp ~~ AddResponse, 'Got AddResponse object';
    is $resp.matched-dn.decode, "uid=jsmith,ou=people,dc=example,dc=com", "Got correct DN";
    is $resp.error-message.decode, 'objectclassinetOrgPersonobjectclassperson', "Sent correct add attributes";
}, "Add request";

# DELETE
subtest {
    my $resp = await $client.delete("cn=Robert Jenkins,ou=People,dc=example,dc=com");
    ok $resp ~~ DelResponse, 'Got DelResponse object';
    is $resp.matched-dn.decode, "cn=Robert Jenkins,ou=People,dc=example,dc=com", "Got correct DN";
}, "Delete request";

# MODIFY DN / RENAME
subtest {
    my $resp = await $client.modifyDN(dn => "cn=Modify Me, o=University of Life, c=US",
            new-dn => "cn=The New Me", :delete, new-superior => "cn=Robert Jenkins,ou=People,dc=example,dc=com");
    ok $resp ~~ ModifyDNResponse, 'Got ModifyDNResponse object';
    is $resp.matched-dn.decode, 'cn=Modify Me, o=University of Life, c=US', 'Get correct DN';
    is $resp.error-message.decode, 'cn=The New Mecn=Robert Jenkins,ou=People,dc=example,dc=com', 'Sent correct attributes';
}, "Modify DN request";

# COMPARE
subtest {
    my $resp = await $client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Smith");
    ok $resp ~~ CompareResponse, 'Got Response::Compare object';
    is $resp.result-code, compareTrue, 'Correct response code';
    is $resp.matched-dn.decode, 'uid=bjensen,ou=people,dc=example,dc=com', 'Got correct DN';
    is $resp.error-message.decode, 'sn=Smith', 'Sent correct attrs';
}, "Compare request";

# ABANDON
subtest {
    my $add-request = $client.add("dc=add", attrs => []);
    lives-ok { $add-request.abandon }, "Abandon method is callable on promise";
    await Promise.anyof(Promise.in(5), $abandon-promise-p);
    is $abandon-promise-p.status, Kept, "Abandon request was sent for a promise";

    my $single-resp = $client.search(:dn<o=myhost>, :filter<cn=root>);
    lives-ok { $single-resp.abandon }, "Abandon method is callable on supply";
    await Promise.anyof(Promise.in(5), $abandon-supply-p);
    is $abandon-supply-p.status, Kept, "Abandon request was sent for search supply";

    my $bind-request = $client.bind;
    throws-like { $bind-request.abandon },
        X::Cro::LDAP::Client::CannotAbandon, message => /'BIND'/;
}, "Abandon operation";

# ROOT DSE
subtest {
    my $root = $client.root-DSE;
    ok $root ~~ Cro::LDAP::RootDSE, "Got Cro::LDAP::RootDSE object";
    ok $root.extensions('1.3.6.1.4.1.4203.1.11.1'), "Has necessary extension by method";
    ok $root<supportedExtension>.decode eq '1.3.6.1.4.1.4203.1.11.1', "Has necessary extension by hash indexing";

    $root = $client.root-DSE('customAttr1', 'customAttr2');
    is $root<customAttr1>.decode, 'foo', "Has customAttr1";
    is $root<customAttr2>.decode, 'bar', "Has customAttr2";
}, "Root DSE";

subtest {
    my $schema = $client.schema;
    ok $schema ~~ Cro::LDAP::Schema, 'Got Cro::LDAP::Shema object';
}, "Schema";

subtest {
    use Cro::LDAP::Control;

    my $control = Cro::LDAP::Control::DontUseCopy.new;
    my $control-resp = await $client.add("uid=bjensen,ou=people,dc=example,dc=com", :attrs(["sn" => "Doe"]),
                controls => [$control]);
    is $control-resp.result-code, compareFalse, 'Got correct result code';
    is $control-resp.matched-dn.decode, 'moc=cd,elpmaxe=cd,elpoep=uo,nesnejb=diu', 'Got correct matched DN';

    $control-resp = await $client.add("uid=bjensen,ou=people,dc=example,dc=com", :attrs(["sn" => "Doe"]),
                controls => [{ type => "1.3.6.1.1.22", :critical },]);
    is $control-resp.result-code, compareFalse, 'Got correct result code';
    is $control-resp.matched-dn.decode, 'moc=cd,elpmaxe=cd,elpoep=uo,nesnejb=diu', 'Got correct matched DN';

}, "Controls";

done-testing;
