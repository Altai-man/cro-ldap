use ASN::Types;

enum ResultCode is export (
        :success(0),
        :operationsError(1),
        :protocolError(2),
        :timeLimitExceeded(3),
        :sizeLimitExceeded(4),
        :compareFalse(5),
        :compareTrue(6),
        :authMethodNotSupported(7),
        :strongAuthRequired(8),
          # 9 reserved
        :referral(10), # new
        :adminLimitExceeded(11), # new
        :unavailableCriticalExtension(12), # new
        :confidentialityRequired(13), # new
        :saslBindInProgress(14), # new
        :noSuchAttribute(16),
        :undefinedAttributeType(17),
        :inappropriateMatching(18),
        :constraintViolation(19),
        :attributeOrValueExists(20),
        :invalidAttributeSyntax(21),
          # 22-31 unused
        :noSuchObject(32),
        :aliasProblem(33),
        :invalidDNSyntax(34),
          # 35 reserved for undefined isLeaf
        :aliasDereferencingProblem(36),
          # 37-47 unused
        :inappropriateAuthentication(48),
        :invalidCredentials(49),
        :insufficientAccessRights(50),
        :busy(51),
        :unavailable(52),
        :unwillingToPerform(53),
        :loopDetect(54),
          # 55-63 unused
        :namingViolation(64),
        :objectClassViolation(65),
        :notAllowedOnNonLeaf(66),
        :notAllowedOnRDN(67),
        :entryAlreadyExists(68),
        :objectClassModsProhibited(69),
          # 70 reserved for CLDAP
        :affectsMultipleDSAs(71), # new
          # 72-79 unused
        :other(80)
          # 81-90 reserved for APIs
);

my role Cro::LDAP::LDAPResult does ASNSequence {
    has ResultCode $.result-code;
    has Str $.matched-dn is OctetString;
    has Str $.error-message is OctetString;
    has Str @.referral is OctetString is optional;

    method ASN-order { <$!result-code $!matched-dn $!error-message @!referral> }
}

role Cro::LDAP::Response {}

class Cro::LDAP::Response::Bind does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    has Str $.server-sasl-creds is OctetString is optional is tagged(7);

    method ASN-order() { <$!result-code $!matched-dn $!error-message @!referral $!server-sasl-creds> }
    method ASN-tag-value { 1 }
}

class PartialAttribute does ASNSequence {
    has Str $.type is OctetString;
    has ASNSetOf[ASN::Types::OctetString] $.vals;

    method new(Str :$type, Positional :$vals) {
        self.bless(:$type, vals => ASNSetOf[ASN::Types::OctetString].new($vals));
    }

    method ASN-order { <$!type $!vals> }
}

class Cro::LDAP::Response::SearchEntry does Cro::LDAP::Response does ASNSequence {
    has Str $.object-name is OctetString;
    has PartialAttribute @.attributes;

    method ASN-order { <$!object-name @!attributes> }
    method ASN-tag-value { 4 }
}

class Cro::LDAP::Response::SearchDone does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    method ASN-tag-value { 5 }
}

class Cro::LDAP::Response::SearchRef does Positional[ASN::Types::OctetString] {
    has @.urls;

    method new(@urls) { self.bless(:@urls) }

    method iterator(Cro::LDAP::Response::SearchRef:D:){ @!urls.iterator }
    method ASN-tag-value { 19 }
}

class Cro::LDAP::Response::Modify does Cro::LDAP::Response does Cro::LDAP::LDAPResult {
    method ASN-tag-value { 7 }
}

class Cro::LDAP::Response::Add does Cro::LDAP::Response does Cro::LDAP::LDAPResult  {
    method ASN-tag-value { 9 }
}

class Cro::LDAP::Response::Del does Cro::LDAP::Response does Cro::LDAP::LDAPResult  {
    method ASN-tag-value { 11 }
}

class Cro::LDAP::Response::ModifyDN does Cro::LDAP::Response does Cro::LDAP::LDAPResult  {
    method ASN-tag-value { 13 }
}

class Cro::LDAP::Response::Compare does Cro::LDAP::Response does Cro::LDAP::LDAPResult  {
    method ASN-tag-value { 15 }
}