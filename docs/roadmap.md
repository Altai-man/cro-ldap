### Roadmap

- [ ] Overview Directory Information Model RFC ([RFC 5412](https://tools.ietf.org/pdf/rfc4512.pdf))
- [x] Implement LDAP URL ([RFC 4516](https://tools.ietf.org/pdf/rfc4516.pdf))
- [x] Implement DN ([RFC 4514](https://tools.ietf.org/pdf/rfc4514.pdf))
- [x] [ASN.1] Recursive schema implementation
- [x] Implement search filters ([RFC 4515](https://tools.ietf.org/pdf/rfc4515.pdf))

##### Authentication

- [ ] Ensure anonymous authentication ([RFC 4513](https://tools.ietf.org/pdf/rfc4513.pdf), 5.1.1)
- [ ] Ensure simple name/password ([RFC 4513](https://tools.ietf.org/pdf/rfc4513.pdf), 5.1.3)
- [ ] * StartTLS operation ([RFC 4513](https://tools.ietf.org/pdf/rfc4513.pdf), 3)
- [ ] * SASL EXTERNAL ([RFC 4513](https://tools.ietf.org/pdf/rfc4513.pdf), 5.2.3)

##### Connection handling

- [ ] Bad request - return a Notice of Disconnection with resultCode set to protocolError, and terminate session
  - [ ] SEQUENCE tag is not recognized
  - [ ] messageID cannot be parsed
  - [ ] Tag of protocolOp is not recognized as a request
- [ ] messageID of a request MUST have a non-zero value, must be different from other values

##### Types

- [ ] LDAPOID is constrained to numericoid
- [ ] LDAPDN is constrained to distinguishedName
- [ ] RelativeLDAPDN is constrained to name-component
- [ ] AttributeDescription is constrained to attributedescription

##### Messages

- [x] Bind
- [x] Add
- [x] Delete
- [x] Compare
- [x] ModDN
- [x] Modify
- [ ] Search
- [ ] Unbind
- [ ] Abandon
- [ ] Extended
- [ ] StartTLS

##### Misc

- [x] Cleanup mess in `Types` (@Xliff++)
