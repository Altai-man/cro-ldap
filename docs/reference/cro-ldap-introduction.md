# Cro::LDAP introduction

This document describes general ideas behind `Cro::LDAP` module, its
scope and general information of such sort that is not related directly
to to the implementation details.

### Purpose

We intend Cro::LDAP to be a quick tool for LDAPv3 support in Perl 6.

Or, more officially, the `Cro::LDAP` module tries to fulfill a number of
goals:

* Provide a LDAP client (a Directory Service Agent, DSA) with interface
  similar to `Net::LDAP` module from Perl 5's `perl-ldap` distribution.
  However, it is not intended as a drop-in replacement, as:
  * The `perl-ldap` distribution provides a wide range of features and
    functions for manipulating LDAP data, while `Cro::LDAP` aims to be a
    slim, streamlined provider for communication with a LDAP server with
    little data transformations.
  * While API is similar to one in `Net::LDAP`, we aim to make
    `Cro::LDAP` to use Perl 6 to its fullest and avoid blind copying
    of the API where possible. Thus, things differ.
* Provide a skeleton for writing a LDAP server in Perl 6. As Cro focuses
  on _serving the data_, not _processing it_, we do not intend to implement
  a Directory Service provider in Perl 6. However, if one desires to
  write a server part with some specific purpose in mind, tying the
  backend is up to the implementor - and `Cro::LDAP` will serve the
  data.
* We provide support for the third version of LDAP specification, using
  [RFC 4510](https://tools.ietf.org/pdf/rfc4510.pdf) as a source.
  Support for second version of the protocol is not planned, but
  eventually possible.

### Further development

While we aim for the goals stated above in the first place, we are open
to implementing other LDAP related code. Just open an issue ticket with
a feature request and we will see how we can help.

### Structure

#### Public API

Main class to interact with a LDAP server is `Cro::LDAP::Client`.

It provides means to connect and send requests to a server, getting
responses to be processed by the end-user code.

```perl6
my $client = Cro::LDAP::Client.connect('ldap://localhost:20000/');
# "Foo" name, simple unauthenticated authentication is used
my $bind = $client.bind(name => "Foo");
die $bind.error-message unless $bind.result-code ~~ success;

react {
    whenever $client.search(base => "c=US", filter => '(&(sn=Barr)(o=Texas Instruments))') -> $entry {
        say "Attributes of $entry.object-name():";
        say " * $_.type() => $_.vals()" for @($entry.attributes);
    }
}
```

Main role to refer to in order to implement a server is called
`Cro::LDAP::Worker`. It requires user to implement a set of methods for
LDAP operations, and handles routing by itself.

```perl6
class MyTinyLDAPServer does Cro::LDAP::Worker {
    method bind($req --> BindResponse) {
        # actual implementation here
    }

    method search($req --> Supply) {
        # actual implementation here
    }

    ...
}
```

It is intended to be used in pair of `Cro::LDAP::Server` class:

```perl6
my Cro::Service $server = Cro::LDAP::Server.new(
        worker => MyTinyLDAPServer.new,
        :$host, :$port);
$server.start;
# ...
$server.stop;
```

#### Internal API

There are number of classes made in order to be pieces of Cro-like flow
(see [The Cro Approach](docs/approach) document).

Data flow of `Cro::LDAP::Client` is:

* `Cro::LDAP::Client` ==> `Cro::LDAP::Message`
* `Cro::LDAP::Message` ==> `Cro::LDAP::MessageSerializer`
* `Cro::LDAP::MessageSerializer` ==> `Cro::TCP::Message`
* `Cro::TCP::Message` ==> *network*
* *network* ==> `Cro::TCP::Message`
*  `Cro::TCP::Message` ==> `Cro::LDAP::MessageParser`
*  `Cro::LDAP::MessageParser` ==> `Cro::LDAP::Message`

Data flow of `Cro::LDAP::Server` is:

* *network* ==> `Cro::TCP::Message`
* `Cro::TCP::Message` ==> `Cro::LDAP::MessageParser`
* `Cro::LDAP::MessageParser` ==> `Cro::LDAP::Message`
* `Cro::LDAP::Message` ==> `Cro::LDAP::Worker`
* `Cro::LDAP::Worker` ==> `Cro::LDAP::Message`
* `Cro::LDAP::Message` ==> `Cro::LDAP::MessageSerializer`
* `Cro::LDAP::MessageSerializer` ==> `Cro::TCP::Message`
* `Cro::TCP::Message` ==> *network*
