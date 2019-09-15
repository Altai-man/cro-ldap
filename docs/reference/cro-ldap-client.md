# Cro::LDAP::Client

#### Synopsis

```perl6
use Cro::LDAP::Client;

my $client = Cro::LDAP::Client.connect('ldap://ldap.example.com/');

$client.bind; # anonymous bind

react {
    whenever $client.search(base => "c=US", filter => '(&(sn=Barr)(o=Texas Instruments))') {
        when Cro::LDAP::Entry {
            say $_; # .gist returns LDIF
        }
        when Cro::LDAP::Reference {
            say $_; # references
        }
    }
}

$client.unbind;

$client = Cro::LDAP::Client.connect('ldap://ldap.example.org/');

$client.bind('cn=root, o=Foos of Bar', password => 'secret');

given await $client.add('cn=One Person, o=Earth, c=US',
                        attrs => ["objectclass" => ["inetOrgPerson","person"],
                                  "mail" => "person@mail.example.com"]) -> $resp {
    if $resp.status {
        say $resp.matchedDN;
        say $resp.msg;
    }
}

$client.unbind;

$client.disconnect;
```

#### Instantiation and connection

The `Cro::LDAP::Client` class is the main class used for communicating
with LDAP server.

It provides methods for sending requests to the LDAP server and can be
used for both one time requests and multi-request communication.

###### connect

```perl6
multi method connect(Str $ldap-url --> Promise) {}
multi method connect(Str :$host, Int :$port --> Promise) {}
```

To create a `Cro::LDAP::Client` instance method `connect` is used:

```perl6
use Cro::LDAP::Client;
my $client = Cro::LDAP::Client.connect('ldaps.host', 389);
# or
my $client = Cro::LDAP::Client.connect('ldap://localhost/');
```

To establish a new connection to the server, `connect` method is used.
It returns a `Promise` object that will be either kept
with the caller `Cro::LDAP::Client` instance or broken depending on a
success or a failure during the connection process.

This method has two candiates. The most commonly used takes a `Str` object with
LDAP URL (according to [RFC 4516](https://tools.ietf.org/pdf/rfc4516.pdf)
as an argument:

    $client.connect('ldap://localhost:20000/');

The second one takes two named arguments, `host` and `port`, both are
optional, which set remote host and port to connect to.

As both are optional, the `connect` method can be called without
arguments, in this case, default values (`localhost` and `380` respectively)
will be used. The same rule applies for the passed LDAP URL that does
not have a port or a host specified.

```perl6
# Defaults

# connects to `ldap://localhost:389/`
my $client = Cro::LDAP::Client.connect;
# connects to `ldap://localhost:389/foo/`
$client = Cro::LDAP::Client.connect('ldap:///foo');
# connects to `ldap://ldap.host:389/`
$client = Cro::LDAP::Client.connect('ldap://ldap.host/');

# Instance attributes

# connects to `ldap://remote.org:390/` 
$client = Cro::LDAP::Client.connect(:host<remote.org>, :port(390));

# Explicit URL

# connects to `ldap://remote2.com:250/`
$client = Cro::LDAP::Client.connect('ldap://remote2.com:250');

# Explicit URL overrides attributes

# connects to `ldap://remote2.com:250/` too
$client = Cro::LDAP::Client.connect(:host<remote.org/>, :port(390));
```

##### Disconnecting

###### disconnect

```perl6
method disconnect() {}
```

`Cro::LDAP::Client` forbids calling `connect` twice and throws an
exception of type `X::Cro::LDAP::Client::DoubleConnect`. It will not
implicitly break the connection and re-connect to the specified host.

In most cases a graceful connection termination is desired and thus
`unbind` method should be preferred over `disconnect`. The `disconnect`
method drops the connection without sending Unbind Request to the server.

```perl6
# Correct
my $client = Cro::LDAP::Client.connect(:host<a.com>); 
# ...
$client.unbind;
$client = $client.connect(:host<b.com>);

# Correct if you don't want unbind message
$client = Cro::LDAP::Client.connect(:host<a.com>);
# ...
$client.disconnect;
$client = $client.connect(:host<b.com>);

# Wrong
my $client = Cro::LDAP::Client.connect(:host<a.com>);
# ... 
$client = Cro::LDAP::Client.connect(:host<b.com>); # throws X::Cro::LDAP::Client::DoubleConnect
```

### Security

#### LDAPS

LDAPS means using normal LDAP communication over TLS layer established
beforehand.

To enable usage of LDAPS, just pass a LDAP URL to `connect` that uses
`ldaps` protocol instead of `ldap`:

```perl6
my $client = await Cro::LDAP::Client.connect("ldaps://localhost:3894");
```

Custom Certificate Authority file can be passed in the same manner as it
is done in Cro::HTTP distribution, just pass a path to Certificate
Authority PEM file as a named parameter:

```perl6
my $client = await Cro::LDAP::Client.connect("ldaps://localhost:3894", :$ca-file);
```

If you are using a `connect` call with host and port passed separately,
you can specify `$is-secure` named `Bool` argument:

```perl6
my $client = await Cro::LDAP::Client.connect(host => "a", port => 6360, :is-secure);
```

The default port for LDAPS connection is 636, which is automatically
 used when `:$is-secure` is enabled and no port value specified.

#### StartTLS

Not yet implemented.

### Operations

All operations must be called on a client instance that was successfully
connected to the server, otherwise the `X::Cro::LDAP::NotConnected`
exception will be thrown. Every operation except `bind` and `unbind` returns
a promise that will be kept with either a response object, a supply of
response objects, or is broken with an exception. The `unbind` operation
has no return value and `bind` operation returns a `BindResponse` object.

For most of the operations, Abandon Operation can be performed, for
details see the `abandon` method description below.

#### bind

```perl6
method bind(Str :$name, :$password --> BindResponse) {}
```

THe `bind` method sends the authentication data to the server. As for
now, only simple authentication mechanisms are supported:

- Anonymous authentication
- Unauthenticated authentication
- Name/Password authentication

To use an anonymous authentication, no arguments are passed. To use
either unauthenticated authentication or name/password authentication,
`name` and `password` arguments can be passed.

According to LDAP rules, no other requests can be send when a
bind operation is in progress, so this method is synchronous.
While other methods can be called concurrently,
an attempt to do so with bind method will result in
blocking await.

It returns an object of `BindResponse` type.
It has all usual components of LDAP Result: `result-code`, `matched-DN`,
`error-message` attributes and an additional attribute
`server-sasl-creds`.

This method accepts controls (see Controls section below).

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
ends an underlying connection. It does not return a value.

This method accepts controls (see Controls section below).

```perl6
$client.unbind;
```

#### SEARCH

```perl6
method search(Str :$dn!, Str :$filter = '(objectclass=*)'',
              Scope :$scope = wholeSubtree,
              DerefAliases :$deref-aliases = derefFindingBaseObj,
              Int :$size-limit = 0, Int :$time-limit = 0,
              Bool :$types-only = False,
              :@attributes = ()) {}
```

The `search` method performs a search request and returns a `Supply`
object that emits either `Cro::LDAP::Entry` objects representing entries
returned from the server or `Cro::LDAP::Reference` objects for returned
references. It takes two required named parameters `$dn` and `$filter`,
both must be `Str` instances that represent base DN to start a search
from and a filter to search with.

Other named arguments can be passed to specify parameters for a search
request, such as size limit, time limit and so on, with defaults
provided.

The `@.attributes` parameter specifies attributes to request from the server,
it accepts a List or an Array of `Str` objects. They are checked to follow
search request attributes syntax and an exception of type
`X::Cro::LDAP::Client::IncorrectSearchAttribute` is thrown.

This method accepts controls (see Controls section below).

```perl6
react {
    whenever $client.search(dn => 'c=foo',
                            filter => '(sn:dn:2.4.6.8.10:=Barney Rubble)') {
        when Cro::LDAP::Entry     { say $_ }
        when Cro::LDAP::Reference { say $_ }

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
entry that is modified and either a pair or an array of pairs that
describe modification operations to send.

Every operation pair must be in format:

```
$operation => $type; # when value is not present, e.g. for delete operation
$operation => $type => 'foo'; # when a single value is present
$operation => $type => ['foo', Buf.new(1, 2, 3), ...]; # when many values are present
```

Here, `$operation` is a key, it must be either `add`, `replace` or
`delete`, and the value is either a `Str` object or a `Pair` object that
describe the attribute to modify. A `Str` or `Pair`s key represent the attribute name
and possible value represents attribute values: values passed there
must be either a `Str` (which will be converted to bytes in
UTF-8), `Buf` (for binary data like images) or an `Array` (can contain
both `Str` and `Buf` items).

This method accepts controls (see Controls section below).

```perl6
my @changes = add => :cn['test'],
        replace => [:cp['test1', 'test2'], :cover(Buf.new($image-buf))],
        delete => ['ck', 'cd'];
$client.modify("cn=modify", @changes);
```

#### ADD

The `add` method takes a `Str` argument and an optional `Positional` of
pairs that represent attributes to be set for the created entry.
If no attributes are passed, an exception of type
`X::Cro::LDAP::Client::EmptyAttributeList` is thrown.

This method accepts controls (see Controls section below).

```perl6
$client.add("cn=add", attrs => [:foo<bar>, :bar<1 2 3>]);
```

#### DELETE

The `delete` method takes a `Str` argument that specified a DN to be
deleted.

This method accepts controls (see Controls section below).

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

This method accepts controls (see Controls section below).

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

This method accepts controls (see Controls section below).

```perl6
$client.compare("uid=bjensen,ou=people,dc=example,dc=com",
                "sn", "Doe");
```

#### ABANDON

Abandon operation is called on a Promise object that is returned from
other methods, such as `add` or `modifyDN`, and is available for a
`Supply` object returned by the `search` routine too.

It is impossible to call the `abandon` method on result of `bind` call,
in this case `X::Cro::LDAP::Client::CannotAbandon` exception will be
thrown.

This method accepts controls (see Controls section below).

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

The method `root-DSE` is used to obtain the `Cro::LDAP::RootDSE` object
that contains information about the server's RootDSE. It takes an
arbitrary number of strings that represent additional attributes to
request for. The attributes passed are additional to default ones:

```
altServer
namingContexts
supportedControl
supportedExtension
supportedFeatures
supportedLDAPVersion
supportedSASLMechanisms
subschemaSubentry
```

The method returns a `Promise` instance which is kept with a `Cro::LDAP::RootDSE` object,
that contains requested attributes.

```perl6
my $root = await $client.root-DSE('customAttribute1', 'customAttribute2');
# Two custom attributes passed as arguments
say $root<customAttribute1 customAttribute2>;
# Supported versions along with other default attributes are always requested and available
say $root.supported-version;
```

### Server Schema

To get the server's schema information a method called `schema` can be
used. A DN to use can be passed as a `Str` object argument. A `Promise` is returned
 which is resolved into an object of type `Cro::LDAP::Schema`.

```perl6
my $schema = await $client.schema;
$schema = await $client.schema($DN);
```

### Controls

Almost all methods that implement operations support sending additional
control values to the server.

Control is a special addition to a message sent to the server or returned
from it. It can alter behavior of the server or allow for the server
to convey additional information.

To add a control to an operation, additional named argument `control` is
passed to a method corresponding to the operation.
Its value can be either an `Cro::LDAP::Control` object or a `Hash`
instance with up to three pairs included:

* `type` - a `Str` value for control's type. Passing a value that does not
  conform to OID syntax causes an exception of type `X::Cro::LDAP::Client::IncorrectOID`
  to be thrown
* `critical` - a `Bool` value indicating if a control is critical, `False` by default
* `value` - a `Buf` value for control's value, absent by default

It allows expressing of any control that can be sent to a server. For
some commonly used control types predefined classes are provided, see
`Cro::LDAP::Control` page for a full list.

```perl6
my $control = Cro::LDAP::Control::DontUseCopy;

# Pass two controls
# Use a predefined type object and a Hash-described equivalent
$client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Doe",
                controls => [
                    $control,
                    { type => "1.3.6.1.1.22", :critical } ]);
# Pass a single control
$client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Doe",
                controls => $control);
```

Response messages can carry controls as well as requests and
they are exposed for every response message as `@.controls` attribute:

```perl6
my $compare-resp = await $client.compare("uid=bjensen,ou=people,dc=example,dc=com", "sn", "Doe");
note $compare-resp.controls;
```

By default, returned server controls can be recognized by Cro::LDAP::Client
or not. If they are recognized, they are converted into an instance of
`Cro::LDAP::Control` role and possibly can be re-used:

```perl6
my $control = Cro::LDAP::Control::Paged.new(:500size);

{
    my $dn = "test=paged";
    my $filter = "cn=root";
    loop {
        # make a search request
        my $search = $client.search(:$dn, :$filter, :$control);
        react {
            # process all values from the search supply
            whenever $search {
                when Cro::LDAP::Entry { #`( process an entry ) }
                when Cro::LDAP::Search::Done {
                    # when this batch is done, find a control of type...
                    my $paged = .controls.first(Cro::LDAP::Control::Paged);
                    # without a control, end the processing
                    last without $paged;
                    # re-use the response cookie for a new request, if any
                    $control.cookie = $paged.cookie;
                }
                QUIT {
                    # an error has happened, we don't want to search for more
                    $client.search(:$dn, :$filter, control => Cro::LDAP::Control::Paged.new(:0size, :cookie($control.cookie)));
                    # process the error
                }
            }
        }
        last unless $control.cookie.elems;
    }
}
```

For unrecognized server-side controls, a Hash of the format specified above
is returned. A callback for parsing the hash can be passed using `:&make-control` named
parameter. When passed, it will be called for every unrecognized
control in the response.

### Extensions

A support for the LDAP Extended Operation is provided and a set
of extensions is provided "out of the box".

To send an extended request the `extend` method is called.
It has two forms: automatic and manual processing.

To execute a response, create an object of a class
provided by Cro::LDAP itself or third-party extensions
and pass it to the `extend` method. This object's data will be used to
send an extended request of specified format, a response will be received
and a specific handler of the extended operation class then gets called
with the response. Result of this call, if any (True otherwise), completes
the `Promise` object that is returned as a result value of the `extend` method.

```perl6
use Cro::LDAP::Extension;

my $name = await $client.extend(Cro::LDAP::Extension::WhoAmI);
note $name;
```

The second form of the `extend` method takes
two arguments: first one is required and represents the
operation's LDAP OID passed as a `Str` object, and optional second argument,
representing extended request value, which is a `Buf` that contains
serialized value of the extended operation request according to ASN.1 rules
used in LDAP. This method returns a `Promise` object that is either
broken with an `X::Cro::LDAP::Client::UnsuccessfulExtended` exception or is kept
with `ExtendedResponse` object for client code to process it manually.

The `X::Cro::LDAP::Client::UnsuccessfulExtended` exception contains `$.response`
attribute with `ExtendedResponse` object assigned.

Manual processing allows user to handle the process directly. It includes:

* Passing the extended operation request name and value (if any) to the `extend` method.
* Receiving and decoding a response object.

Note that request name that does not conform to LDAP OID rules
passed will cause an exception of type `X::Cro::LDAP::Client::IncorrectOID`
to be thrown.

```perl6
use ASN::Types;
use ASN::Serializer;

class CancelRequestValue does ASNSequence {
    has Int $.cancelID is required;

    method ASN-order { <$!cancelID> }
}

my $cancel-value = CancelRequestValue.new(cancelID => 65);

my $op-name = "1.3.6.1.1.8";
my $op-value = ASN::Serializer.serialize($cancel-value);
my $resp = await $client.extend($op-name, $op-value);
# process $resp...
with $resp.response-name {
    say "Response name is ", $_.decode; # $.response-name is Buf
}
with $resp.response {
    ...
}
```
