use Text::LDIF;

class X::Cro::LDAP::LDIF::CannotParse is Exception {
    method message() { "Cannot parse LDIF" }
}

enum LDIF::Operation <ldif-add ldif-delete ldif-modify ldif-moddn ldif-modrdn>;

class Cro::LDAP::Entry does Associative {
    has Str $.dn is rw;
    has LDIF::Operation $.operation is rw;
    has %.attributes is rw handles <AT-KEY EXISTS-KEY>;

    method parse(Str $ldif-str) {
        my $ldif = Text::LDIF.parse($ldif-str);
        die X::Cro::LDAP::LDIF::CannotParse.new unless $ldif;

        my @items;

        for $ldif<entries><> {
            # note $_;
        }

        for $ldif<changes><> -> $change {
            my $entry = self.new;
            $entry.dn = $change<dn>;

            my $operation = $change<change>;
            # e.g. 'delete' operation does not have attributes
            if $operation !~~ Str {
                # If it is a Pair, we need to populate attributes and unwrap it
                # so that it could be used in Operation setting code
                $operation .= key;
                self.populateAttributes($change, $entry);
            }
            # Text::LDIF always has a changetype correct when parsed, so no checks here
            $entry.operation = LDIF::Operation(LDIF::Operation.enums{'ldif-' ~ $operation});

            @items.push: $entry;
        }

        @items;
    }

    method populateAttributes($change, $entry) {
        my @attributes;

        if $change<change>.key eq 'modify' {
            # Text::LDIF returns us an array of attributes to modify,
            # but here we translate it into a classified Hash we can query later
            @attributes = $change<change>.value.classify(*.key, as => *.value);
        } else {
            @attributes = $change<change>.value<>;
        }

        for @attributes -> $attr {
            when $attr.value ~~ Pair {
                # The structure is:
                # foo => file => file://...
                # Check if it is `file`:
                my $attr-type = $attr.value.key;
                if $attr-type eq 'file' {
                    # Get `file` and remove prefix
                    my $path = $attr.value.value.substr(7);
                    # Try to load contents of the file
                    my $buf = try slurp $path, :bin;
                    # When the file is present, add, otherwise warn and skip
                    with $buf {
                        $entry{$attr.key} = $buf;
                    } else {
                        note "File not found at '$path' for DN '$entry.dn()', skipping...";
                    }
                } else {
                    warn "Encountered an attribute of type $attr.perl(), NOT YET IMPLEMENTED";
                }
            }
            when $attr.value ~~ Seq {
                $entry{$attr.key} = $attr.value.List;
            }
            default {
                $entry{$attr.key} = $attr.value;
            }
        }
    }
}