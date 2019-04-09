# Cro::LDAP::Client

#### Synopsis

```perl6
use Cro::LDAP::Client;

my $client = Cro::LDAP::Client.connect('ldap.example.com');

await $client.bind; # anonymous bind

react {
    whenever $client.search(base => "c=US", filter => '(&(sn=Barr)(o=Texas Instruments))') -> $entry {
        say $entry; # .gist returns LDIF
    }
}

await $client.unbind;

$client = Cro::LDAP::Client.connect('ldap.example.org');

await $client.bind('cn=root, o=Foos of Bar', password => 'secret');

given await $client.add('cn=One Person, o=Earth, c=US',
                        ["objectclass" => ["inetOrgPerson","person"],
                         "mail" => "person@mail.example.com"]) -> $resp {
    if $resp.status {
        say $resp.matchedDN;
        say $resp.msg;
    }
}

await $client.unbind;
```

#### Instantiation and connection

```perl6
use Cro::LDAP::Client;
```

The `Cro::LDAP::Client` class is a main class used for communicating
with LDAP server.

It provides methods for sending requests to the LDAP server and can be
used for both one time requests and multi-request communication.

To create a `Cro::LDAP::Client` instance, normal `new` constructor is
used:

```perl6
my $client = Cro::LDAP::Client.new;
```

If the same object won't be re-used with different remote hosts, `host`
and `port` parameters can be passed: default values are `localhost` and
`389` respectedly.

To establish a new connection to the server, `connect` method should be
used. The `connect` method returns a `Promise` that will be either kept
or broken depending on success or failure during the connection process.
It takes a LDAP URL (according to
[RFC 4516](https://tools.ietf.org/pdf/rfc4516.pdf) as a parameter:

    $client.connect('ldap://localhost:20000/');

The `connect` method can be called without arguments, in this case,
instance's `host` and `port` values will be used. The same rule applies
for the passed LDAP URL that does not have a port or a host specified.

```perl6
# Defaults

# connects to `ldap://localhost:389/`
my $client = Cro::LDAP::Client.new.connect;
# connects to `ldap://localhost:389/foo/`
$client = Cro::LDAP::Client.new.connect('ldap:///foo');
# connects to `ldap://ldap.host:389/`
$client = Cro::LDAP::Client.new.connect('ldap://ldap.host/');

# Instance attributes

# connects to `ldap://remote.org:390/` 
$client = Cro::LDAP::Client.new(:host<remote.org/>, :port(390)).connect;

# Explicit URL

# connects to `ldap://remote2.com:250/`
$client = Cro::LDAP::Client.new.connect('ldap://remote2.com/250');

# Explicit URL overrides attributes

# connects to `ldap://remote2.com:250/` too
$client = Cro::LDAP::Client.new(:host<remote.org/>, :port(390)).connect('ldap://remote2.com/250');
```

As a shortcut, the `connect` method can be called on `Cro::LDAP::Client`
object directly. In this case, the method will create a
`Cro::LDAP::Client` instance and will use it to do a connection,
returning the created object:

```perl6
my $client = Cro::LDAP::Client.connect('ldap://remote.org:389');
```

### Operations

All operations must be called on a client instance that was successfully
connected to the server, otherwise `X::Cro::LDAP::NotConnected`
exception will be thrown. Every operation except `unbind` returns a
promise that will be kept with either a response object, a supply of
response objects, or broken with an exception. The `unbind` operation
has no return value.

#### BIND

Sends authentication data to the server. As for now, only simple
authentication mechanisms are supported:

- Anonymous authentication
- Unauthenticated authentication
- Name/Password authentication

```perl6
# anonymous authentication -> name and password are empty
given await $client.bind -> $resp {
    die "Oh no, error! Status code is $resp.code()";
};
# unauthenticated authentication for logging purposes
$client.bind(name => "foo");
# TLS is negotiated and established before executing bind request,
# if TLS is set to True for the client instance, and won't be otherwise
$client.bind(name => "foo", password => "password");
```

#### UNBIND

Sends an unbind request to the server and gracefully ends an underlying
connection.

```perl6
$client.unbind;
```

#### SEARCH

Performs a search request and returns a supply that will emit entries.

```perl6
react {
    whenever $client.search(dn => 'c=foo',
                            filter => '(sn:dn:2.4.6.8.10:=Barney Rubble)') -> $entry {
        say $entry;

        LAST { say "No more entries!" }
        QUIT {
            default {
                say "Something went bad!"
            }
        }
}
```

#### MODIFY

The `modify` method takes a `Str` value of the directory name of the
entry that is modified and either a pair or array of pairs that describe
modification operations to send.

Every operation pair must be in format:

```
$operation => { :$type, :values(['foo', Buf.new(1, 2, 3), ...]) }
```

Here, `$operation` is a key, it must be either `add`, `replace` or
`delete`, and the value is a hash with `type` and `values` elements. The
`type` element is a `Str` object with the attribute name. The `values`
element is optional (considered to be an empty array by default): its
value must be either a `Str` (which will be converted to bytes in
UTF-8), `Buf` (for binary data like images) or an `Array` (can contain
both `Str` and `Buf` items).

```perl6
my @changes = add => { :type<name>, :vals(['Tester']) },
    replace => { :type<songs>, :vals(['Chase the Grain', 'Chase the Grain']) },
    delete => { :type<cover>, :vals(Buf.new($image-buf)) };
$client.modify("cn=modify", @changes);
```

#### ADD

#### DELETE

#### MODIFY DN

#### COMPARE

#### ABANDON

#### StartTLS
