class Cro::LDAP::Entry does Associative {
    has Str $.dn;
    has %.attributes handles <AT-KEY EXISTS-KEY>;
}
