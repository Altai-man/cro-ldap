enum ResultCode (:success(0));

class Cro::LDAP::Result {
    has ResultCode $.result-code;
    has LDAPDN $.matchedDN;
    has LDAPString $.diagnosticMessage;
    has Referral $.referral;
}
