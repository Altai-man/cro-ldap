## Overall architecture of LDAP implementation with Cro

Data flow of Client is:

* `Cro::LDAP::Client` -> `Cro::LDAP::Request`
* `Cro::LDAP::Request` -> `Cro::LDAP::RequestSerializer` -> `Cro::TCP::Message` -> *network*
* *network* -> `Cro::TCP::Message` -> `Cro::LDAP::ResponseParser` -> `Cro::LDAP::Response`

Data flow of Server is:

* *network* -> `Cro::TCP::Message`
* `Cro::TCP::Message` -> `Cro::LDAP::RequestParser` -> `Cro::LDAP::Request` -> *server*
* *server* -> `Cro::LDAP::Response` -> `Cro::LDAP::ResponseSerializer` -> `Cro::TCP::Message` -> *network*
