class Cro::LDAP::RootDSE does Associative {
    has %.attributes handles <AT-KEY EXISTS-KEY>;

    method new(Hash $attributes) {
        self.bless(:$attributes);
    }

    method extensions(*@extensions --> Bool) {
        so set(%!attributes<supportedExtension>){@extensions};
    }

    method features(*@features --> Bool) {
        so %!attributes<supportedFeatures>{@features}.all
    }

    method controls(*@controls --> Bool) {
        so %!attributes<supportedControl>{@controls}.all
    }

    method versions(*@versions --> Bool) {
        so %!attributes<supportedLDAPVersion>{@versions}.all
    }

    method sasl-mechanisms(*@mechs --> Bool) {
        so %!attributes<supportedSASLMechanisms>{@mechs}.all
    }
}