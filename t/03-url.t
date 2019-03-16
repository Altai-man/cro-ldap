use Test;
use Cro::LDAP::URL;
plan *;

sub parses($desc, $url, *@checks) {
    with try Cro::LDAP::URL.parse($url) -> $parsed {
        subtest {
            for @checks.kv -> $i, $check {
                ok $check($parsed), "Check {$i + 1}";
            }
        }, $desc;
    }
    else {
        diag "LDAP URI parsing failed: $!";
        flunk $desc;
        skip "Failed to parse", @checks.elems;
    }
}

parses "empty URL", "ldap:///",
        *.hostname eq "",
        *.port eq 389,
        *.DN eq [],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "hostname", "ldap://example.com/",
        *.hostname eq "example.com",
        *.port eq 389,
        *.DN eq [],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "host:port", "ldap://example.com:1234",
        *.hostname eq "example.com",
        *.port eq 1234,
        *.DN eq [],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 1",
        "ldap:///o=University%20of%20Michigan,c=US",
        *.hostname eq "",
        *.port eq 389,
        *.DN eq ["o=University%20of%20Michigan", "c=US"],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 2",
        "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US",
        *.hostname eq "ldap1.example.net",
        *.port eq 389,
        *.DN eq ["o=University%20of%20Michigan", "c=US"],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 3",
        "ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress",
        *.hostname eq "ldap1.example.net",
        *.port eq 389,
        *.DN eq ["o=University%20of%20Michigan", "c=US"],
        *.attributes eq ["postalAddress"],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 4",
        "ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
        *.hostname eq "ldap1.example.net",
        *.port eq 6666,
        *.DN eq ["o=University%20of%20Michigan", "c=US"],
        *.attributes eq [],
        *.scope eq "sub",
        *.filter eq "cn=Babs%20Jensen",
        *.extensions eq "";

parses "complex url 5",
        "LDAP://ldap1.example.com/c=GB?objectClass?ONE",
        *.hostname eq "ldap1.example.com",
        *.port eq 389,
        *.DN eq ["c=GB"],
        *.attributes eq ["objectClass"],
        *.scope eq "one",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 6",
        "ldap://ldap2.example.com/o=Question%3f,c=US?mail",
        *.hostname eq "ldap2.example.com",
        *.port eq 389,
        *.DN eq ["o=Question%3f", "c=US"],
        *.attributes eq ["mail"],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 7",
        "ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)",
        *.hostname eq "ldap3.example.com",
        *.port eq 389,
        *.DN eq ["o=Babsco", "c=US"],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "four-octet=%5c00%5c00%5c00%5c04",
        *.extensions eq "";

parses "complex url 8",
        "ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US",
        *.hostname eq "ldap.example.com",
        *.port eq 389,
        *.DN eq ["o=An%20Example%5C2C%20Inc.", "c=US"],
        *.attributes eq [],
        *.scope eq "base",
        *.filter eq "objectClass=*",
        *.extensions eq "";

parses "complex url 9",
        "ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com",
        *.hostname eq "",
        *.port eq 389,
        *.DN eq [],
        *.attributes eq [],
        *.scope eq "sub",
        *.extensions eq ["e-bindname=cn=Manager%2cdc=example%2cdc=com"];

parses "complex url 10",
        "ldap:///??sub??!e-bindname=cn=Manager%2cdc=example%2cdc=com",
        *.hostname eq "",
        *.port eq 389,
        *.DN eq [],
        *.attributes eq [],
        *.scope eq "sub",
        *.extensions eq ["!e-bindname=cn=Manager%2cdc=example%2cdc=com"];

done-testing;
