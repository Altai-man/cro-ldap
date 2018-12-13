### Roadmap

##### Connection handling

- [ ] *ASN* Unify index and length handling
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

- [x] Unbind request

- [x] Search request
- [x] Search result entry
- [x] Search result done
- [x] Search result reference

- [ ] Modify request
- [ ] Modify response

- [ ] Add request
- [ ] Add Response

- [ ] Delete request
- [ ] Delete response

- [ ] Modify DN request
- [ ] Modify DN response

- [ ] Compare Operation
- [ ] Compare Response

- [x] Abandon request

- [ ] Unsolicited Notification - a message from server to client about some special conditions
