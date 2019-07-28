# Cro::LDAP::Server

#### Synopsis

```perl6
use Cro::LDAP::Server;
use Cro::LDAP::Worker;

class MyLDAPWorker does Cro::LDAP::Worker {
    method add($req, :@controls --> AddResponse) {}
    method modify($req, :@controls --> ModifyResponse) {}
    method search($req, :@controls --> Supply) {}
    method compare($req, :@controls --> CompareResponse) {}
    method bind($req, :@controls --> BindResponse) {}
    method modifyDN($req, :@controls --> ModifyDNResponse) {}
    method abandon($req, :@controls) {}
    method unbind($req) {}
    method delete($req, :@controls --> DelResponse) {}
}

my Cro::Service $server = Cro::LDAP::Server.new(
        worker => MyLDAPWorker.new,
        :$host, :$port);
$server.start;
```
