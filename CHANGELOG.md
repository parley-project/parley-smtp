# Changelog

## parley-smtp 2.0.0 (unreleased)

### Changed (2026-10-26: each server alone, shared assets carry their own settings)

- **Each SMTP server reads only its own settings, under its own prefix**, and the queue carries its own:
  - A server's settings are about its port: `hostname` (required; no default from the machine's name),
    `requireTls`, `relayNetworks`, the limits, the checks of incoming mail and its queue, `<prefix>.queue`
    (default `.smtp-queue` under the maildrop root). A submission server reads `parley.mail.submission.*` from
    the start (it used to read the relay's settings).
  - Whether a server is a relay or a submission server comes from how it is made
    (`new SmtpServer(port, name, secure, submission)`); the setting `parley.mail.smtp.submission` is gone.
  - The queue's settings are in `queue.properties` in its directory, without a prefix: `hostname` and `domains`
    (required), the smart host (`relayPassword` must name where the password is kept, `@keychain:...`,
    `@file:...` or `@env:...`), the resolver, DKIM signing, ARC sealing, DMARC reports, workers, retry and the
    history. They replace `parley.mail.smtp.domains`, `.relayHost`, `.queue.workers`, `.dkim.keys` ... and
    `parley.mail.smtp.queue.history*`. A queue without them isn't used.
  - Each server opens its own queue; servers given the same queue share it through the store's locks, as servers
    in separate processes would. The JVM-wide shared queue (`SmtpProviders.SharedQueue`) is gone, and each
    server's queue is the JMX bean `MailQueue,name=<its id>`.
  - No setting is derived from another: the domains aren't the host name, DMARC reports need
    `dmarc.reportOrgName` and `dmarc.reportEmail`, and ARC seals only with an `arc.domain`.

### Added
- **`historyFileSource`** (queue setting): the file system the history's folder is on, a FileSource type id such as `FileProxy`
  for local disk; default the mail root's. It needs `historyDirectory` unless it is the mail root's own type.
  `QueueHistory.folder(mailRoot, fileSource, directory)` finds the folder, for an application that reads the history.
  A mail store in a database no longer has to hold the log: on B1 (500 messages, MySQL) the log was 3 of 7 `file_data`
  inserts and 3 of 23 commits per message.

- One DKIM key for every domain: the queue setting `dkim.shared` names the domain whose key signs mail from each
  local domain without a key of its own, with the same selector and that local domain as d= (DMARC alignment).
  With Parley DNS each domain inherits the key's record from the primary domain's zone, so it needs no zone file.
  `Dkim.setShared`/`sharedSignerFor`, `DkimSigner.forDomain`, `DeliveryConfig.localDomainOf`/`dkimSignerFor`; the
  queue's reload reads it again too, and refuses a shared domain with no key.

- `MailQueueMXBean.reload()` (and `MailQueue.reload()`): the queue reads its domains, aliases file and DKIM keys
  again and uses them at once, with no restart. Every one is read before any is used, so nothing changes when
  one can't be read. `DeliveryConfig.setLocalDomains`, `setAliases` and `parseAliases`, and `Dkim.setSigners`
  and `parseSigners`, replace them whole. parley-mail-admin calls it after a domain, alias or DKIM change.

- **`SmtpProviders`**: parley-net `ServerProvider`s `smtp`, `submission` and `submissions`, so SMTP runs alone or with
  other servers in one process (parley-net's `ServerMain`), and is managed with JMX. Each server's queue is the JMX bean
  `us.bringardner.parley:type=MailQueue,name=<id>` (`MailQueueMXBean`, `QueuedMessageInfo`, `QueuedRecipientInfo`).
  Each SMTP server's JMX bean lists its open connections (parley-net's `ParleyServerMBean.getConnectionList()`).
- **The queue's history** (`QueueHistory`): every `QueueEvent` as a JSON line in `<root>/.smtp-history/smtp-YYYY-MM-DD.jsonl`,
  30 days kept (`parley.mail.smtp.queue.history`, `.historyDirectory`, `.historyDays`). `SmtpServer.getQueueHistory()`.
  Written through the mail root's FileSource (any store), a line at a time with the file closed again, so
  processes sharing a queue write the same files.
- The DMARC reporter of a queue SMTP servers share stops with the last of them, not the first.

### Changed

- `SmtpServer.main` runs the providers with `ServerMain.launch`: `parley-mail.properties` is read before
  `parley-smtp.properties`, and `submissions` runs when `parley.mail.submissions.port` is set. With every port 0 it
  says there is nothing to run.
- **`SmtpServer.main` runs the server as a service** with parley-net's `ServerMain.run`: settings from the command
  line (which wins) and `parley-smtp.properties` in Parley's administrator folder (`/etc/parley`, or the file the server's
  `configFile` property names); it stops on SIGTERM; the relay and the submission servers start and stop together; a failed start exits with 1.
  With `parley.mail.smtp.port=0` it runs only the submission servers (the queue runs with them) instead of
  listening on a random port; with every SMTP port 0 it refuses to start.

### Changed (needs a configuration change)

- **Property names** (Parley 2.0.0; the old names are no longer read): `JSmtp.*` is `parley.mail.smtp.*`
  (`parley.mail.smtp.domains`, `.relayHost`, `.dkim.keys`, `.queue.retry` ...), and the maildrop root is the shared
  `parley.mail.root` / `parley.mail.fileSource`. `JSmtp.properties` is `parley.mail.smtp.configFile`.
- Each listener reads its own settings (key store, limits, access control) with its prefix: `parley.mail.smtp`
  (was `SmtpServer`), `parley.mail.submission` for a submission server and `parley.mail.submissions` with
  implicit TLS (`setSubmission(true)` switches the prefix). `JSmtp.submissionPort` / `JSmtp.submissionsPort` are
  `parley.mail.submission.port` / `parley.mail.submissions.port`.
- `JSmtp.loginFailureDelay` is now the server's `loginFailureDelay`.

### Added

- **Queue events** for an application's history of the queue: `MailQueue.addQueueListener(QueueListener)` reports
  `QueueEvent`s: QUEUED, then per recipient DELIVERED, DEFERRED, FAILED or EXPANDED after each attempt, and
  COMPLETED when the message leaves the queue (DELETED for `delete`).
- **Administering the queue:** `MailQueue.getEntry(id)`, `getContent(id)` (the message, to read), `retry(id)` (one
  message now) and `delete(id)` (remove a message without delivering or bouncing it; never one being
  delivered). `QueuedRecipient.getNextAttempt()`.
- **Virtual domains:** with several local domains, an alias or user can belong to one domain (an alias
  `sales@example.com`, a user named `tony@example.com`); those without a domain still receive mail for every local
  domain. Aliases are looked up before users, and the full address before the local part (`+detail` ignored as
  before) (`LocalDelivery.find(MailAddress)`, used by RCPT and local delivery).

### Fixed

- `SmtpStreams.CrlfOutputStream.write(byte[], int, int)` writes the bytes between line ends as one
  block instead of a byte at a time (the output is the same).

## parley-smtp 1.1.0 (unreleased)

### Added

- When the access control list can't answer (its database is down): AUTH gets `454 4.7.0` (RFC 4954, try again
  later), not counted as a failure (`SmtpRequestProcessor.isLoginUnavailable()`); RCPT TO a local user gets
  `451 4.3.0` instead of "user unknown", and queued mail for local users is tried again later instead of
  bounced.
- **SCRAM-SHA-256 and SCRAM-SHA-1** for `AUTH`, offered in EHLO when the server's access control list keeps SCRAM
  credentials for every user (parley-net 1.1.0: `FileBasedAcl --scram`, or parley-net-acl-jdbc). The user is
  logged in with `SmtpRequestProcessor.loginVerified(user)` after the proof, with the same permission checks as a password login.
- **Several servers on one queue** (parley-mail 1.1.0's `parley.mail.sharedStore`): each delivery pass holds the
  message's lock (`queue/<dir>/<id>`, through parley-net's locks), skips a message another server holds, and
  starts from the envelope on disk; a shared queue picks up the other servers' messages every few seconds
  (`MailQueue.setSyncInterval`, `isShared()`) and removes only temporary files over an hour old.
- DMARC reports in a shared directory: logs per server, one server sending at a time, one report per domain with
  every server's evaluations, and `.last-sent` for one timed sending per interval (`DmarcReporter.flushIfDue()`).

### Changed (no code change needed)

- Local delivery goes through parley-mail's `MailStore.deliver`, the one way new mail gets into a store.
- The queue starts after the server has claimed the store (`AbstractMailServer.storeClaimed()`) and stops before
  the claim is given up (`releasingStore()`).
- An envelope is written to a temporary file of its own and replaces the old one in one step where the store can.
- A flush sends one aggregate report per policy domain, whatever log files its evaluations are in.
- Dependencies: parley-mail and parley-net 1.1.0; their tests jars for tests (the shared test users and helpers). No longer parley-pop3, even for
  tests.

## parley-smtp 1.0.0 (2026-10-16)

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
