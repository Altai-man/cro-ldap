class Cro::LDAP::Reference does Positional does Iterable {
    has @.refs handles <elems AT-POS EXISTS-POS STORE>;

    method iterator(Cro::LDAP::Reference:D:) {
        @!refs.iterator;
    }
}
