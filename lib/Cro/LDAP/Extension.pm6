use Cro::LDAP::Types;

role Cro::LDAP::Extension {
    method message { ... }
    method callback() { ... }
}

class Cro::LDAP::Extension::WhoAmI does Cro::LDAP::Extension {
    has $!OP-CODE = "1.3.6.1.4.1.4203.1.11.3";

    method callback(ExtendedResponse $resp) {
        $resp.response.decode;
    }

    method message {
        ExtendedRequest.new(request-name => $!OP-CODE);
    }
}
