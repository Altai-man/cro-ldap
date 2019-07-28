use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
use Cro::LDAP::Client;
use Cro::LDAP::Control;
use Cro::LDAP::Entry;
use Cro::LDAP::Reference;
use Cro::LDAP::Schema;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Test;

plan *;

# Connection
sub prepare-server($host = 'localhost', $port = 3890) {
    my Cro::Service $server = Cro::LDAP::Server.new(
            worker => MockLDAPWorker.new,
            :$host, :$port);
    $server.start;
    $server;
}

{
    my $conn = Cro::LDAP::Client.connect(:host<localhost>, :port(3891));
    ok $conn ~~ Promise, "connect method returns a Promise";
    todo "Abilities are overestimated", 1;
    dies-ok { await $conn }, "Connection dies";
#    ok $conn.status ~~ Broken, "connect Promise is broken if no server available";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;

    lives-ok {
        my $conn = await Cro::LDAP::Client.connect(:host<localhost>, :port(3890));
        ok $conn ~~ Cro::LDAP::Client:D, "connect method resolves into caller Cro::LDAP::Client";
    }, "Can connect to a working server";
}

{
    my $server = prepare-server;
    LEAVE $server.stop;
    lives-ok {
        await Cro::LDAP::Client.connect("ldap://localhost:3890/");
    }, "Can connect using canonical LDAP URL";
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
        $client.unbind;
        $client.connect(port => 3890);
    }, "Can connect after disconnection";
    lives-ok {
        my $client = await Cro::LDAP::Client.connect("ldap://localhost:3890/");
        $client.unbind(controls => [{ type => "1.3.6.1.1.22", :critical },]);
        $client.connect(port => 3890);
    }, 'Unbind can take manual control';
    lives-ok {
        my $client = await Cro::LDAP::Client.connect("ldap://localhost:3890/");
        $client.unbind(controls => [Cro::LDAP::Control::DontUseCopy.new]);
        $client.connect(port => 3890);
    }, 'Unbind can take automatic control';
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
throws-like { Cro::LDAP::Client.extend("") }, X::Cro::LDAP::Client::NotConnected,
        message => /'extended'/, "Cannot send Extended Request when no connection";

# Checkers for unusual operations

my $unbind-p = Promise.new;
my $abandon-promise-p = Promise.new;
my $abandon-supply-p = Promise.new;

my @CHECKS = [
    (* ~~ UnbindRequest, $unbind-p),
    (* ~~ 10, $abandon-promise-p),
    (* ~~ 12, $abandon-supply-p)
];

my Cro::Service $server = Cro::LDAP::Server.new(
        worker => MockLDAPWorker.new(:@CHECKS),
        :host('localhost'),
        :20000port);
$server.start;
END $server.stop;

my Cro::LDAP::Client $client = await Cro::LDAP::Client.connect('ldap://localhost:20000/');

# BIND
subtest {
    my $resp;

    $resp = $client.bind;
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Anonymous bind", "Recognized as anonymous bind";

    $resp = $client.bind(name => "cn=manager,o=it,c=eu");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Unauthenticated bind", "Recognized as unauthenticated bind";

    $resp = $client.bind(name => "cn=manager,o=it,c=eu", password => "secret");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, success, "Returned correct result code";
    is $resp.error-message.decode, "Normal bind", "Recognized as name/password bind";
    is $resp.server-sasl-creds.decode, "CustomCreds", "SASL server creds were received";

    $resp = $client.bind(name => "dn=no-more");
    ok $resp ~~ BindResponse, 'Got Response::Bind object';
    is $resp.result-code, busy, "Returned correct result code";
}, "Bind request-response";

subtest {
    $client.unbind;
    await Promise.anyof(Promise.in(5), $unbind-p);
    is $unbind-p.status, Kept, "Unbind request was sent";
    $client = await Cro::LDAP::Client.connect('ldap://localhost:20000/');
}, "Unbind request";

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
            if $number-of-refs == 0 {
                is-deeply $ref.refs,
                        ["ldap://hostb/OU=People,DC=Example,DC=NET??sub", "ldap://hostf/OU=Consultants,OU=People,DC=Example,DC=NET??sub"],
                        'References are decoded';
            }
            $number-of-refs++;
        }
    }
    is $number-of-responses, 20, "Got 20 responses";
    is $number-of-refs, 5, "Got 5 references";

}, "Search request";

# MODIFY
subtest {
    my $modify-resp = await $client.modify("cn=modify1", add => name => 'Tester');
    ok $modify-resp ~~ ModifyResponse, "Got ModifyResponse object";
    is $modify-resp.matched-dn.decode, "cn=modify1", "Got correct DN";
    is $modify-resp.error-message.decode, "addnameTester", "Sent correct change";

    my @changes = add => [:cn['test']],
            replace => [:cp['test1', 'test2']],
            delete => ['ck'];
    $modify-resp = await $client.modify("cn=modify15", @changes);
    ok $modify-resp ~~ ModifyResponse, "Got ModifyResponse object";
    is $modify-resp.matched-dn.decode, "cn=modify15", "Got correct DN";
    ok $modify-resp.error-message.decode ~~ "addcntestreplacecptest1 test2deleteck" ||
       $modify-resp.error-message.decode ~~ "addcntestreplacecptest2 test1deleteck", "Sent correct change set";
}, "Modify request";

# ADD
subtest {
    throws-like {
        $client.add("dc=com", attrs => ())
    }, X::Cro::LDAP::Client::EmptyAttributeList, 'Adding an entry without attributes throws an exception';
    my $resp = await $client.add("uid=jsmith,ou=people,dc=example,dc=com",
            attrs => ["objectclass" => "inetOrgPerson", "objectclass" => "person"]);
    ok $resp ~~ AddResponse, 'Got AddResponse object';
    is $resp.result-code, success, 'Got correct result code';
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
    my $add-request = $client.add("dc=add", attrs => [foo => '42']);
    lives-ok { $add-request.abandon }, "Abandon method is callable on promise";
    await Promise.anyof(Promise.in(5), $abandon-promise-p);
    is $abandon-promise-p.status, Kept, "Abandon request was sent for a promise";

    my $single-resp = $client.search(:dn<o=myhost>, :filter<cn=root>);
    lives-ok { $single-resp.abandon }, "Abandon method is callable on supply";
    await Promise.anyof(Promise.in(5), $abandon-supply-p);
    is $abandon-supply-p.status, Kept, "Abandon request was sent for search supply";
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
    my $control = Cro::LDAP::Control::DontUseCopy.new;
    my $control-resp = await $client.add("uid=bjensen,ou=people,dc=example,dc=com", :attrs(["sn" => "Doe"]),
                controls => [$control]);
    is $control-resp.result-code, compareFalse, 'Got correct result code';
    is $control-resp.matched-dn.decode, 'moc=cd,elpmaxe=cd,elpoep=uo,nesnejb=diu', 'Got correct matched DN';

    throws-like {
        $client.add("", :attrs[:foo<bar>], controls => [{ type => 'error', :critical },]);
    }, X::Cro::LDAP::Client::IncorrectOID, message => /'error'/, 'Incorrect control type syntax throws';
    throws-like {
        $client.add("", :attrs[:foo<bar>], controls => [{ :critical },]);
    }, X::Cro::LDAP::Client::IncorrectOID, message => /'no type'/, 'Empty control type throws';

    $control-resp = await $client.add("uid=bjensen,ou=people,dc=example,dc=com", :attrs(["sn" => "Doe"]),
                controls => [{ type => "1.3.6.1.1.22", :critical },]);
    is $control-resp.result-code, compareFalse, 'Got correct result code';
    is $control-resp.matched-dn.decode, 'moc=cd,elpmaxe=cd,elpoep=uo,nesnejb=diu', 'Got correct matched DN';
    # Server-side controls
    my $resp = await $client.add("uid=jsmith,ou=people,dc=example,dc=com",
            attrs => ["objectclass" => "inetOrgPerson", "objectclass" => "person"]);
    is $resp.controls.elems, 1, 'Server-side control was added';
    is $resp.controls[0].control-type, '1.3.6.1.1.22', 'Server-side control type is decoded';
    ok $resp.controls[0].criticality, 'Server-side control is marked as critical';
}, "Controls";

subtest {
    is (await $client.extend(Cro::LDAP::Extension::WhoAmI.new)), 'dc=local', 'Formed extend request out of type';
    is $client.extend("1.3.6.1.4.1.4203.1.11.3").result.response.decode, 'dc=local', 'Manual extended operation';
    throws-like {
        $client.extend("error");
    }, X::Cro::LDAP::Client::IncorrectOID, message => /'error'/, 'Operation OID is checked';
}, 'Extended operation';

# Sync tests

subtest {
    my $ldif = q:to/END/;
version: 1
# Add a new entry
dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com
changetype: add
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Fiona Jensen
sn: Jensen
uid: fiona
telephonenumber: +1 408 555 1212
jpegphoto:< file://t/testdata/test.jpg
END
    my @entries = Cro::LDAP::Entry.parse($ldif);
    my @p = await $client.sync(@entries);
    is @p[0].error-message, Blob.new, 'Error message is empty';

    $ldif = q:to/END/;
version: 1
# Delete an existing entry
dn: cn=Robert Jensen, ou=Marketing, dc=airius, dc=com
changetype: delete

# Modify an entry’s relative distinguished name
dn: cn=Paul Jensen, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: cn=Paula Jensen
deleteoldrdn: 1

# Rename an entry and move all of its children to a new location in
# the directory tree (only implemented by LDAPv3 servers).
dn: ou=PD Accountants, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: ou=Product Development Accountants
deleteoldrdn: 0
newsuperior: ou=Accounting, dc=airius, dc=com
END
    @entries = Cro::LDAP::Entry.parse($ldif);
    @p = await $client.sync(@entries);

    $ldif = q:to/END/;
version: 1
# Modify an entry: add an additional value to the postaladdress
# attribute, completely delete the description attribute, replace
# the telephonenumber attribute with two values, and delete a specific
# value from the facsimiletelephonenumber attribute
dn: cn=Paula Jensen, ou=Product Development, dc=airius, dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

# Modify an entry: replace the postaladdress attribute with an empty
# set of values (which will cause the attribute to be removed), and
# delete the entire description attribute. Note that the first will
# always succeed, while the second will only succeed if at least
# one value for the description attribute is present.
dn: cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com
changetype: modify
replace: postaladdress
-
delete: description
-
END
    @entries = Cro::LDAP::Entry.parse($ldif);
    @p = await $client.sync(@entries);
}, 'Sync method';

done-testing;
