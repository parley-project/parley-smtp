# Changelog

## parley-smtp 1.0.0 (unreleased)

The SMTP server, queue, DKIM, SPF, DMARC and ARC code of BjlEmail (`us.bringardner:bjl_email`
1.0.0-SNAPSHOT, never released) is now **parley-smtp**, part of the Parley library family.

### Changed (needs a code change)

- Maven coordinates: `us.bringardner.parley:parley-smtp`.
- Packages: `us.bringardner.net.smtp` (and `.dkim`, `.dmarc`, `.queue`, `.server`, `.spf`) is now
  `us.bringardner.parley.smtp`.
- `BjlDnsMxResolver` is now `ParleyDnsMxResolver`.
- `LocalDelivery` uses the mail store from parley-mail (`us.bringardner.parley.mail.store`) and its
  `MailboxConstants` instead of the IMAP module, so SMTP no longer depends on IMAP.
- Module name (`Automatic-Module-Name`): `us.bringardner.parley.smtp`.
- Dependencies: `parley-mail`, `parley-net`, `parley-dns`; `parley-pop3` and snakeyaml for tests only.

### Changed (no code change needed)

- `JSmtp.resolver` takes `parley-dns` and `parley-dns-iterative`; the old `bjldns` and
  `bjldns-iterative` still work.
- The server's greeting, `Received:` headers and DMARC report `User-Agent` say `Parley` instead of `BjlEmail`.

### Added

- `JSmtp.relayAuth` / `DeliveryConfig.setRelayAuthMechanisms`: SASL mechanisms for logging in to the
  smart host, best first (SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5, PLAIN, LOGIN). The first one the
  smart host offers is used. The default (none) is AUTH PLAIN as before.
- `SmtpClient.authenticate(ISaslClient)`, `chooseSasl(...)` and `getCapabilities()` (the EHLO
  extensions as a parley-net `CapabilitySet`). A SCRAM login fails if the server says 235 without
  having proved it knows the password.

### Internal

- AUTH runs through parley-net's `SaslServerDriver`, with `SmtpSaslAuthenticator` supplying the
  login, and the EHLO extension list is built from a `CapabilityRegistry`. The replies, status
  codes and the advertised `AUTH PLAIN LOGIN` are the same as before. Requires a parley-net that
  has the `capability` and `sasl` packages.
- The session state checks (HELO before MAIL, MAIL before RCPT, ...) stay in the commands: BDAT
  must read and discard its chunk before it can answer a bad sequence, and DATA with no
  recipients is a 554, not a 503, so a state check ahead of the command doesn't fit SMTP.
- `SmtpStreams.DotStuffingOutputStream` is parley-io's `DotStuffingOutputStream` with bare CR
  normalized; the stuffing logic is no longer duplicated here. Requires a parley-io that has it.

### Unchanged

- The `JSmtp.*` / `SmtpServer.*` properties and the queue files on disk (header `BJLQUEUE 1`).
