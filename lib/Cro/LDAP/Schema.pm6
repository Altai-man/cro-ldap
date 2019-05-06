class Cro::LDAP::Schema does Associative {
    has %.attributes handles <AT-KEY EXISTS-KEY>;

    method new(Hash $attributes) {
        self.bless(:$attributes);
    }
}
