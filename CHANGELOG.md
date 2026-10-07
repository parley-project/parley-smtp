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

### Unchanged

- The `JSmtp.*` / `SmtpServer.*` properties and the queue files on disk (header `BJLQUEUE 1`).
