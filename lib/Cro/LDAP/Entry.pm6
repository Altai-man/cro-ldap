use Text::LDIF;

class X::Cro::LDAP::LDIF::CannotParse is Exception {
    method message() { "Cannot parse LDIF" }
}

class Cro::LDAP::Entry does Associative {
    enum Operation <add delete modify moddn modrdn>;

    has Str $.dn is rw;
    has Operation $.operation is rw;
    has %.attributes is rw handles <AT-KEY EXISTS-KEY>;

    method parse(Str $ldif-str) {
        my $ldif = Text::LDIF.parse($ldif-str);
        die X::Cro::LDAP::LDIF::CannotParse.new unless $ldif;

        my @items;

        for $ldif<entries> {
            note $_;
        }

        for $ldif<changes><> {
            note $_;
            my $item = self.new;

            $item.dn = $_<dn>;

            my $operation = $_<change>;
            if $operation !~~ Str {
                $operation .= key if $operation !~~ Str;
                $item.attributes = $_<change>.value;
            }
            # Text::LDIF always has a changetype correct when parsed, so no checks here
            $item.operation = Operation(Operation.enums{$operation});

            @items.push: $item;
        }

        @items;
    }
}
