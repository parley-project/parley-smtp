# Changelog

## parley-smtp 2.0.0 (unreleased)

### Added (2026-11-08: the sender check, To-Do 16.8)

- **A logged-in user's sender addresses are checked** (MAIL FROM and every address in the From: header): their own
  address and aliases that list them are allowed; any other address needs the new `sendAs` permission on the server
  as a whole (`SmtpCommand.SEND_AS`, `SEND_AS_PERMISSION`). Refused: `553 5.7.1` at MAIL FROM, `550 5.7.1` after DATA
  (before DKIM signing); `451 4.7.0` when the registry can't answer. Before this, a logged-in user could send as any
  address, and mail for a hosted domain was signed with that domain's DKIM key. Sessions with no login
  (`relayNetworks`, mail from outside) are unchanged.
- **`SmtpRequestProcessor.checkSender(MailAddress)`** and **`HeaderFields.addresses(String)`** (every address of an
  address field, groups included).

### Changed (2026-11-06: users, logins and permissions come from parley-iam)

- **parley-smtp uses parley-iam and the new parley-net**: the server's user registry (a parley-iam `UserRegistry`,
  from `parley.mail.users` or `authenticationProvider`) checks AUTH and is where local recipients are looked up.
  `SmtpCommand.SEND_PERMISSION` is a `ParleyPermission` (`write`), and `BaseCommand.getPermission()` returns one.
- **AUTH replies**: `535 5.7.8` for bad credentials or a user without the send permission; `454 4.7.0` when the
  registry can't answer now, for the login or for the send-permission check (never `535` for that, and not counted).
- **Failed logins are counted by parley-net** (the session's login limits: the delay before the `535`, and the
  `421 4.7.0` close after `maxLoginAttempts`, now sent from `replyTooManyLoginFailures()`). Removed: SMTP's own
  counting and `loginFailedDelay()` calls.
- **`SmtpSaslAuthenticator` extends parley-mail's `MailSaslAuthenticator`** and adds the send-permission check; a
  SCRAM login is finished with its `verified(user)`, and a failed exchange is counted with `exchangeFailed(reason)`.
- **`SmtpRequestProcessor.login(user, password)` returns an `AuthenticationResult`** (it returned a boolean).
  Removed: `loginVerified(String)` (use `SmtpSaslAuthenticator.verified`) and `isLoginUnavailable()` (the
  UNAVAILABLE result replaces it).
- **`DeliveryConfig.getUserRegistry()` / `setUserRegistry(UserRegistry)`** replace `getAccessControl()` /
  `setAccessControl(IAccessControlList)`. Local delivery reads the `maildrop` attribute of the principal (it was a
  parameter); a group is not a recipient.


### Changed (2026-11-03: To-Do 15.3)

- **`main` registers each server's store bean**: while they run, the servers `main` runs have their stores as
  `us.bringardner.parley:type=MailStore,name=<id>` (smtp, submission, submissions) on the platform MBean server (parley-mail's
  `MailServerMain`), so their mailbox ACLs can be managed without an application.

### Changed (2026-11-03: the launcher moved to parley-mail-admin)

- **`SmtpProviders` (the providers smtp, submission, submissions) moved to parley-mail-admin** with the launcher, which runs the mail suite; this module
  registers no server providers. Its `main` runs its servers alone in one process with parley-net's `ServerMain.run`
  (its settings file and the command line, as system properties; the implicit TLS server only when there is a TLS
  key store), not through the launcher.

### Changed (2026-11-02: parley-net's IAccessControlList.close, To-Do 3.3)

- **Local delivery uses the server's access control list of the current start**: a list the server made from its
  `authenticationProvider` setting is closed when the server stops and made again when it starts, so the queue the
  server made is given the new one at each start.

### Changed (2026-11-02: durations and the smart host's names, To-Do 2.19)

- **Times are durations, with the unit in the value** (`30s`, `5m`, `4h`, `5d`; parley-core's `Durations`). A number
  without a unit is **milliseconds**, so a 1.x `retry=1,5,15` must become `retry=1m,5m,15m` (a wait under a second
  gets a warning).
  - The queue's `maxAge` (was `maxAgeHours`), `delayWarning` (was `delayWarningHours`), `dmarc.reportInterval` (was
    `dmarc.reportIntervalHours`) and `retry` (was minutes). A wrong value refuses the queue, naming the setting.
  - Each SMTP server's `timeout`, `pregreet.delay` (was `pregreet.millis`) and `spam.timeout` (was
    `spam.timeoutMillis`). The spam engine gives providers their limit as `SpamProvider.TIMEOUT` (`timeout`, was
    `TIMEOUT_MILLIS`, `timeoutMillis`); `Spam.getTimeoutMillis()`.
- **The queue's smart host is `smartHost.*`**: `smartHost` (the host only; a `host:port` value refuses the queue),
  `smartHost.port` (default 587), `smartHost.user`, `smartHost.password` (where the password is kept, as before),
  `smartHost.auth` and `smartHost.tls`, replacing `relayHost`, `relayUser`, `relayPassword`, `relayAuth` and
  `relayTls`. Who may relay through the server stays `relayNetworks`.
- **The smart host's password is resolved as SMTP's** (`SmtpServer.CREDENTIALS_ID`, `smtp`), with the host and user,
  so `parley.credentials.smtp.keyStore` (parley-files) chooses its key store.
- The queue's old names are no longer read; each one still in `queue.properties` gets a warning naming its new one.
  The renamed server settings are in `META-INF/parley/settings.list`, so the start-up check names theirs too.
- parley-dns's root servers file is `root.hints` (was `sbelt.prop`) in the docs of the iterative resolver.

### Changed (2026-11-01: parley.servers says which servers run, To-Do 2.12)

- **`submissions` runs on 465 when `parley.servers` lists it** and it has a TLS key store (skipped with a warning while
  it has none); `parley.mail.submissions.port` is only its port, and port 0 no longer turns a server off.
- **No relay with implicit TLS**: `parley.mail.smtp.secure` (the relay on implicit TLS, on `parley.mail.smtps.port`,
  whose default was 25) and `parley.mail.smtps.port` are no longer read; a warning says so. RFC 8314's implicit TLS
  is submission's (`submissions`); the relay is SMTP with STARTTLS.
- **No relay with implicit TLS in code either** (To-Do 2.17): `new SmtpServer(port, name, true)` and
  `new SmtpServer(port, name, true, false)` throw IllegalArgumentException, as does `setSubmission(false)` on a
  submission server with implicit TLS; `SmtpServer.SMTPS_PREFIX` is removed. Use `submissionServer(true)`.

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
- **The settings this module reads are listed** in `META-INF/parley/settings.list`, so a Parley server's
  start-up check (parley-net's `KnownSettings`, To-Do 2.16) knows them and warns only about a setting
  nothing reads. A test checks the list has every name the code here reads.
- **Spam providers, found at run time** (`us.bringardner.parley.smtp.spam`): after a message from outside is received
  (with its SPF/DKIM/DMARC results already in the headers) and before it is accepted, the SMTP server asks a spam
  scanner for a `SpamVerdict` (score, spam or not, the scanner's own action, the rules that matched).
  - **The API**: a `SpamProvider` describes a kind of scanner (`getId`, `getTitle`, `getDescription`, `getFeatures`:
    `CHECK`, `LEARN`, `STATUS`; `getSettings`, the same `ConnectionSetting`s FileSource connections use, with kinds,
    defaults, choices, secrets and advanced settings; `validate`) and makes a `SpamFilter` (`check`, `learn(request,
    spam)`, `status()` giving a `SpamStatus`: reachable, version, message).
  - **Discovery** is as FileSourceFactory's (parley-core's `Plugins`): `SpamProviders` finds the classes listed in
    `META-INF/services/us.bringardner.parley.smtp.spam.SpamProvider` in the class path and the plugin folders, and
    `SpamProviders.register` adds one by code. No provider is known by name: this module's own `none`, `rspamd` and
    `spamassassin` are listed in its services file like any plug-in. `SpamProviders.test` asks a provider's scanner
    whether it answers with a form's settings.
  - **Providers included**: `none` (checks nothing); `rspamd` (`/checkv2`; learning through its controller; `/ping`
    for the status and version); `spamassassin` (spamd SYMBOLS; learning with TELL, which needs spamd's
    `--allow-tell`; PING for the status).
  - **Settings are the SMTP server's own** (`spam.*` under its prefix, `parley.mail.smtp.spam.*`; only the server that
    receives mail from other servers checks): `enabled` (default false), `provider` (default `none`),
    `rejectScore` / `quarantineScore` (when set, the score decides; otherwise the provider's action, or Junk for what it
    calls spam), `maxSize` (2 MB), `timeoutMillis` (5000) and `<id>.<key>` for each provider's own (`rspamd.url`,
    `rspamd.password`, `rspamd.controllerUrl`, `spamassassin.host`, `.port`, `.user`). They are read when the server
    starts; settings that are wrong are logged and the earlier ones kept.
  - **Per-domain overrides are the queue's** (`spam.domains` in `queue.properties`, `example.com:off,other.org:rspamd`:
    a recipient domain's own choice, which also works when checking is off for the rest), and are read again by a reload
    of the queue, so the Domains page applies them at once.
  - A message is refused (550 5.7.1), deferred (451 4.7.1), delivered to Junk, or accepted with `X-Spam-Flag`,
    `X-Spam-Score`, `X-Spam-Status` and `X-Spam-Checker` (the sender's own fields of those names are removed). Recipients
    with different providers are checked once per provider and the mildest outcome wins. A provider that fails or is slow
    never stops mail: it is accepted unscored and the failure is logged. Mail from relay clients is not checked.
- **Checks of the client before any mail** (relay ports; all off by default, skipped for clients that may relay by
  a trusted network or a login), settings under the server's prefix:
  - `dnsbl.zones` (comma separated): a connecting address listed in a DNS block list gets `554 5.7.1` and is
    disconnected. Private addresses are never asked; `127.255.255.x` answers (a refused query) and DNS failures
    are not listings; answers are kept for 10 minutes. Not made on a submission port.
  - `rdns.require`: MAIL is answered `450 4.7.25` if the client address has no PTR name that resolves back to it.
  - `helo.check`: HELO/EHLO is answered `550 5.7.1` for a name that is not fully qualified (or an address literal)
    or that is this server's name or one of its domains.
  - `pregreet.millis`: wait this long before the greeting; a client that sends first gets `554 5.5.0`.
  - `rate.connectionsPerMinute`, `rate.maxConcurrent` (`421 4.7.0` at connect), `rate.messagesPerMinute` (MAIL) and
    `rate.recipientsPerMinute` (RCPT) (`450 4.7.1`), per client address.
  - `checks.logOnly`: report what would be refused without refusing, to try a rule on live mail first.
  `SmtpServer.getConnectionChecks()` gives the same settings to code (`us.bringardner.parley.smtp.abuse`).
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
