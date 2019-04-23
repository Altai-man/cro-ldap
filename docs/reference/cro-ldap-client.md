# Cro::LDAP::Client

#### Synopsis

```perl6
use Cro::LDAP::Client;

my $client = Cro::LDAP::Client.connect('ldap://ldap.example.com/');

await $client.bind; # anonymous bind

react {
    whenever $client.search(base => "c=US", filter => '(&(sn=Barr)(o=Texas Instruments))') -> $entry {
        say $entry; # .gist returns LDIF
    }
}

await $client.unbind;

$client = Cro::LDAP::Client.connect('ldap://ldap.example.org/');

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

$client.disconnect;
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
$client = Cro::LDAP::Client.new.connect('ldap://remote2.com:250');

# Explicit URL overrides attributes

# connects to `ldap://remote2.com:250/` too
$client = Cro::LDAP::Client.new(:host<remote.org/>, :port(390)).connect('ldap://remote2.com:250');
```

As a shortcut, the `connect` method can be called on `Cro::LDAP::Client`
object directly. In this case, the method will create a
`Cro::LDAP::Client` instance and will use it to do a connection,
returning the created object:

```perl6
my $client = Cro::LDAP::Client.connect('ldap://remote.org:389');
```

##### Disconnecting

To disconnect from the server, just call `disconnect` method:

```perl6
$client.disconnect;
```

### Operations

All operations must be called on a client instance that was successfully
connected to the server, otherwise `X::Cro::LDAP::NotConnected`
exception will be thrown. Every operation except `unbind` returns a
promise that will be kept with either a response object, a supply of
response objects, or broken with an exception. The `unbind` operation
has no return value.

#### BIND

THe `bind` method sends the authentication data to the server. As for
now, only simple authentication mechanisms are supported:

- Anonymous authentication
- Unauthenticated authentication
- Name/Password authentication

To use an anonymous authentication, no arguments are required. To use
either unauthenticated authentication or name/password authentication,
`name` and `password` fields can be passed.

```perl6
# anonymous authentication -> name and password are empty
given await $client.bind -> $resp {
    die "Oh no, error! Status code is $resp.code()";
};
# unauthenticated authentication for logging purposes
$client.bind(name => "foo");
# name/password authentication
$client.bind(name => "foo", password => "password");
```

#### UNBIND

The `unbind` method sends an unbind request to the server and gracefully
ends an underlying connection.

```perl6
$client.unbind;
```

#### SEARCH

The `search` method performs a search request and returns a `Supply`
object that emits either `Cro::LDAP::Entry` objects for entries returned
from the server or `Cro::LDAP::Search::Reference` objects for returned
references.

```perl6
react {
    whenever $client.search(dn => 'c=foo',
                            filter => '(sn:dn:2.4.6.8.10:=Barney Rubble)') {
        when Cro::LDAP::Entry { say $_ }
        when Cro::LDAP::Search::Reference { say $_ }

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

The `add` method takes a `Str` argument and an optional `Positional` of
pairs that represent attributes to be set for the created entry.

This method accepts controls.

```perl6
$client.add("cn=add", attrs => [:foo<bar>, :bar<1 2 3>]);
```

#### DELETE

The `delete` method takes a `Str` argument that specified a DN to be
deleted.

```perl6
$client.delete("cn=Robert Jenkins,ou=People,dc=example,dc=com");
```

#### MODIFY DN

The `modifyDN` method takes two mandatory arguments, `dn` and `new-dn`,
both are `Pair` objects that represent old and new DN respectedly. To
set a deletion flag for the old DN, `delete` boolean named attribute can
be passed. It defaults to `False`. To set a new superior DN, optional
`new-superior` named argument can be used - it must be a `Str` instance
with value of new superior DN for the renamed entry.

```perl6
$client.modifyDN(:dn('cn=Modify Me, o=University of Life, c=US'),
                 :new-dn('cn=The New Me'));
# or
$client.modifyDN(
        dn => "cn=Modify Me, o=University of Life, c=US",
        new-dn => "cn=The New Me",
        :delete,
        new-superior => "cn=Robert Jenkins,ou=People,dc=example,dc=com");
```

#### COMPARE

The `compare` method takes three mandatory, positional arguments: a
`Str` object that represents a DN of the entry to use for the request, a
`Str` object that represents name of the attribute to compare and a
`Str` object that represents a value to compare with.

```perl6
$client.compare("uid=bjensen,ou=people,dc=example,dc=com",
                "sn", "Doe");
```

#### ABANDON

Abandon operation is called on a Promise object that is returned from
other methods, such as `add`, and is available for a `Supply` objects
returned too.

This method accepts controls.

```perl6
my $add-request = $client.add(...);
$add-request.abandon;
# or a supply
react {
    my $search-request = $client.search(dn => 'c=foo',
                                        filter => '(sn:dn:2.4.6.8.10:=Barney Rubble)');
    # we don't need more after three seconds
    Promise.in(3).then({ $search-request.abandon });     
    whenever $search-request -> $entry {
        # process $entry
    }
}
```

### Root DSE

The method `get-root-DSE` is used to obtain the `Cro::LDAP::RootDSE`
object that contains information about server's rootDSE. It takes an
arbitrary number of strings that represent attributes to request for.
The attributes passed are additional to default ones:

```
subschemaSubentry
namingContexts
altServer
supportedExtension
supportedFeatures
supportedControl
supportedSASLMechanisms
supportedLDAPVersion
```

The method returns a `Cro::LDAP::RootDSE` object that contain requested
attributes.

```perl6
my $root = await $client.get-root-DSE('customAttribute1', 'customAttribute2');
# Two custom attributes passed as arguments
say $root<customAttribute1 customAttribute2>;
# Supported versions along with other default attributes are always requested and available
say $root.supported-version;
```

### Server Schema

To get server's schema information a named called `schema` can be used.
A DN to use can be passed as a `Str` object argument. An object of class
`Cro::LDAP::Schema` is returned.

```perl6
my $schema = $client.schema;
$schema = $client.schema($DN);
```

### Controls

Almost all methods that implement operations support sending additional
control values to the server.

To add a control to an operation, additional named argument `control` is
passed. Its value can be an `Cro::LDAP::Control` object or a `Hash`
instance with up to three pairs included:

* `type` - a `Str` value for control's type
* `critical` - a `Bool` value for control's criticality (its default
  value - `False`)
* `value` - a `Str` value for control's value, absent by default

It allows for expressing any control that can be send to a server. For
commonly used controls a predefined classes are provided, see
`Cro::LDAP::Control` page for a full list.

```perl6
my $control = Cro::LDAP::Control::DontUseCopy;

# Pass two controls
# Use a predefined type object or a Hash-described equivalent
$client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Doe",
                controls => [
                    $control,
                    { type => "1.3.6.1.1.22", :criticality }]);
# Pass a single control
$client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Doe",
                controls => $control);
```

### Extensions

A general support for LDAP Extended Operation is provided and a set of
specific extensions supported by `perl-ldap` package is included.

In general case, to send an extended request a `extend` method is called
with two named arguments: `name` is required and represents the
operation's LDAP OID passed as `Str` object, and `value`, which is an
instance of a class that can be serialized using `ASN::Serializer`
class. In case if the extended request does not include a value, it can
be omitted.

To use included extensions from `Cro::LDAP::Extension` compunit, an
instance of particular class is constructed and passed to `extend`
method. A listing of supported extensions and their interfaces is
described in `Cro::LDAP::Extension` compunit documentation.

```perl6
use ASN::Types;

class CancelRequestValue does ASNSequence {
    has Int $.cancelID is required;

    method ASN-order { <$!cancelID> }
}

my $cancelValue = CanceLRequestValue.new(cancelID => 65);

my $resp = await $client.extend(
    name => "1.3.6.1.1.8",
    value => $cancelValue
);

# Or, if using an included type, just
use Cro::LDAP::Extension;

my $resp = await $client.extend(Cro::LDAP::Extension::Cancel.new(65));
```
