# parley-smtp

SMTP for **Parley**, a family of Java libraries for implementing internet protocols: an SMTP server
and mail transfer agent (RFC 5321). It receives mail, delivers it into the `parley-mail` store (the
same mailboxes `parley-imap` and `parley-pop3` serve), and relays mail for other domains through a
persistent queue. It signs and checks DKIM, checks SPF and DMARC (with aggregate reports) and handles ARC.

Requires Java 11 or later. Depends on `parley-mail`, `parley-net` and `parley-dns` (which bring in
`parley-files`, `parley-core` and `parley-io`).

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-smtp</artifactId>
    <version>1.0.0</version>
</dependency>
```

> parley-smtp was split out of `us.bringardner:bjl_email` (BjlEmail). `us.bringardner.net.smtp` is now
> `us.bringardner.parley.smtp`, and `BjlDnsMxResolver` is now `ParleyDnsMxResolver`. The `JSmtp.*` and
> `SmtpServer.*` properties are unchanged; `JSmtp.resolver` now takes `parley-dns` and
> `parley-dns-iterative`, and still accepts the old `bjldns` and `bjldns-iterative`.

## Build

```
mvn package
```

Tests run with a 64 MB heap, so message bodies must stay out of memory.

## The server

`SmtpServer` follows the same design:

| parley-ftp | parley-smtp | Role |
|---|---|---|
| `FtpServer` | `SmtpServer` | Accepts connections, holds the configuration |
| `FtpRequestProcessor` | `SmtpRequestProcessor` | Runs one session |
| `FtpCommandFactory` | `SmtpCommandFactory` | Maps command names to command classes |
| `FtpCommand`, `commands.*` | `SmtpCommand`, `commands.*` | One class per command |
| `FTP` | `SMTP` | Protocol constants |

Behind the sessions is `MailQueue` (package `us.bringardner.parley.smtp.queue`). It delivers mail locally, relays it to other servers and sends delivery status notifications.

```java
SmtpServer relay = new SmtpServer();               // port 25
relay.setMaildropRoot(rootFileSource);             // the same root as POP3 and IMAP
relay.addLocalDomain("example.com");
relay.start();

SmtpServer submission = SmtpServer.submissionServer(false);   // port 587
submission.setQueue(relay.getQueue());             // one queue for both
submission.start();

relay.send(from, List.of(to), message);            // send mail from code
```

Or from the command line: `java us.bringardner.parley.smtp.server.SmtpServer -DJSmtp.domains=example.com -DJSmtp.root=/var/mail/pop3`. This starts port 25 and, unless `JSmtp.submissionPort=0`, port 587.

### Protocol support

The server follows RFC 5321 and its pending revision, draft-ietf-emailcore-rfc5321bis (in the RFC Editor queue). It supports:

| Extension | RFC |
|---|---|
| PIPELINING | 2920 |
| SIZE | 1870 |
| 8BITMIME | 6152 |
| SMTPUTF8 | 6531 |
| ENHANCEDSTATUSCODES | 2034, 3463 |
| CHUNKING and BINARYMIME (BDAT) | 3030 |
| DSN | 3461, 3464, 6533 |
| STARTTLS | 3207 |
| AUTH PLAIN and LOGIN | 4954, 4616 |
| Message submission | 6409 |
| Implicit TLS (port 465) | 8314 |
| Null MX | 7505 |

- **Commands:** EHLO, HELO, MAIL, RCPT, DATA, BDAT, RSET, NOOP, QUIT, VRFY (always 252), EXPN (502), HELP, STARTTLS and AUTH.
- **Received headers** name the protocol per RFC 3848 and RFC 6531, e.g. `ESMTPSA` or `UTF8SMTPS`.
- **Protections:**
  - Only CRLF `.` CRLF ends DATA, which defeats "SMTP smuggling". A `.` after a bare LF is content.
  - A message with more than 100 Received headers is refused as a loop.
  - HTTP requests are refused.
  - The session closes after 20 errors or 3 failed logins.

### Who can send what

- **Mail for the local domains** (`JSmtp.domains`) is accepted from anyone, but only for existing users, aliases and `postmaster`. Unknown users get `550 5.1.1`. A `+detail` suffix is ignored when looking up the user.
- **Mail for other domains** is accepted only from authenticated users (who need the WRITE permission) or from `JSmtp.relayNetworks`. Everyone else gets `550 5.7.1 Relay access denied`, so the server is not an open relay.
- **Submission servers** (port 587/465) require AUTH and add `Date` and `Message-ID` when they're missing.
- **requireTls:** with `JSmtp.requireTls`, AUTH is offered only after STARTTLS. It is off by default, as for POP3 and IMAP; turn it on for submission on a public network.

### The queue and delivery

- **Safe before 250:** accepted mail is written to `<root>/.smtp-queue` (an `.eml` and an `.env` file per message) before the server replies 250. It survives a restart.
- **Local delivery** goes into the user's INBOX, the same maildrop POP3 and IMAP use. It adds `Return-Path` and `Delivered-To`. IMAP sessions in the same process see the new message at once.
- **Aliases:** `JSmtp.aliases` names a file of lines like `sales: tony, jose@example.org`. Members may be local users or remote addresses. Alias loops are stopped.
- **Remote delivery:**
  - The queue looks up MX records. With no MX record it uses the domain's own address, and a null MX means the domain takes no mail.
  - Two resolvers are included, chosen with `JSmtp.resolver`:
    - `jdk` (default): `DnsMxResolver`, the JDK's DNS provider.
    - `parley-dns`: `ParleyDnsMxResolver`, which makes every DNS request with parley-dns: the MX query and the A/AAAA lookups of the mail hosts. It asks the servers in `JSmtp.dnsServers` (comma-separated), or those in `/etc/resolv.conf`, in turn.
    - `parley-dns-iterative`: parley-dns's own iterative resolver, which starts from the root servers in its `sbelt.prop`.
    - Any other `MxResolver` can be set with `getDeliveryConfig().setResolver(...)`.
  - It tries hosts in order of preference, with opportunistic STARTTLS.
  - It uses SIZE, 8BITMIME, SMTPUTF8, CHUNKING/BINARYMIME and DSN when the message needs them. A message needing SMTPUTF8 is returned (5.6.7) by a server without it, as RFC 6531 requires.
- **Smart host:** set `JSmtp.relayHost=host:port` (with `JSmtp.relayUser`/`JSmtp.relayPassword`) to send all outgoing mail through your provider. Many home and cloud networks block outgoing port 25. The smart host requires TLS with a valid certificate (`JSmtp.relayTls`).
- **Retries:** temporary failures are retried on `JSmtp.queue.retry` (minutes, default `1,5,15,30,60,120`).
  - The sender gets a "delayed" notice after `JSmtp.queue.delayWarningHours` (default 4).
  - The message is returned after `JSmtp.queue.maxAgeHours` (default 120).
- **Notifications** are RFC 3464 multipart/report messages from `MAILER-DAEMON`.
  - They honour NOTIFY, RET, ENVID and ORCPT.
  - For UTF-8 addresses or messages they use `message/global-delivery-status` and `message/global`.
  - A notification is never sent about a notification.

### DKIM (RFC 6376)

The server signs outgoing mail and verifies the signatures of incoming mail. The code is in `us.bringardner.parley.smtp.dkim`, and all DNS lookups go through parley-dns.

**Signing.** Mail from authenticated users and from `JSmtp.relayNetworks` is signed with the key of its From domain. A key for `example.com` also signs mail from `news.example.com`. Bounces and mail sent from code (`send`, `MailQueue.enqueue`) are signed the same way. Mail with no matching key is sent unsigned.

- RSA keys sign with `rsa-sha256`, and Ed25519 keys with `ed25519-sha256` (RFC 8463; Ed25519 needs Java 15 or later at run time).
- Signatures use relaxed/relaxed canonicalization. They cover the usual fields (From, To, Cc, Subject, Date, Message-ID, MIME fields, List-* fields...), and the main ones are "over-signed" so a second From or Subject can't be added later.
- The DKIM-Signature field goes at the top of the message. Delivery never changes the content, so the signature stays valid.

To set up a key:

```
java -cp parley-smtp.jar:... us.bringardner.parley.smtp.dkim.DkimKeys rsa /etc/dkim/example.com.pem
```

This writes the private key (PKCS#8 PEM) and prints the TXT record to publish at `<selector>._domainkey.example.com`, for example `mail2026._domainkey.example.com`. Then set `JSmtp.dkim.keys=example.com:mail2026:/etc/dkim/example.com.pem`, with more keys separated by commas. Keys from openssl work too (`-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`), but not encrypted ones. In code:

```java
relay.getDkim().addSigner(new DkimSigner("example.com", "mail2026", DkimKeys.privateKey(new File("/etc/dkim/example.com.pem"))));
```

**Verifying.** Mail from other servers (clients that are neither authenticated nor in `JSmtp.relayNetworks`) is checked, and the result is added after our Received field:

```
Authentication-Results: mx.example.com;
	dkim=pass header.d=example.org header.i=@example.org header.s=sel1 header.a=rsa-sha256 header.b=AbCd1234
```

- The results are `pass`, `fail` (the body or header hash doesn't match), `permerror` (bad signature, no key, revoked key, rsa-sha1, RSA keys under 1024 bits), `temperror` (DNS failed), or `none` (no signature). Up to 5 signatures are checked.
- The message is accepted whatever the result. Rejecting is a policy decision, for DMARC to make.
- Authentication-Results fields that claim to come from this server (`JSmtp.hostname`) are removed first (RFC 8601 section 5).
- The body is hashed as it streams from the queue file, so large messages are never held in memory.
- Keys are looked up with the `parley-dns` resolver's DNS servers when `JSmtp.resolver=parley-dns` (or `parley-dns-iterative`). Otherwise the servers in `/etc/resolv.conf` are asked through parley-dns. Turn verification off with `JSmtp.dkim.verify=false`.

### SPF (RFC 7208)

For mail from other servers (clients that are neither authenticated nor in `JSmtp.relayNetworks`), the server checks whether the client's address may send for the MAIL FROM domain. For a null reverse-path (`MAIL FROM:<>`, as in bounces), it checks the HELO name instead. The code is in `us.bringardner.parley.smtp.spf`, and every DNS query goes through parley-dns.

- **What's supported:** every mechanism (`all`, `include`, `a`, `mx`, `ptr`, `ip4`, `ip6`, `exists`), the `redirect` and `exp` modifiers, and macros. The processing limits apply: at most 10 DNS-querying terms, 2 void lookups, and 10 MX or PTR names.
- **Recording the result:** a `Received-SPF` field (RFC 7208 section 9.1) goes after our Received field. The result is also added to Authentication-Results, next to the DKIM results:

  ```
  Received-SPF: pass (mx.example.com: domain of user@example.org designates 192.0.2.1 as permitted sender)
  	receiver=mx.example.com; client-ip=192.0.2.1; envelope-from="user@example.org"; helo=mail.example.org; mechanism=ip4:192.0.2.0/24; identity=mailfrom;
  Authentication-Results: mx.example.com;
  	spf=pass smtp.mailfrom=example.org;
  	dkim=pass header.d=example.org ...
  ```
- **Results:** `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror` (DNS failed) or `permerror` (a broken record, or too many lookups).
- **Rejecting:** by default the message is accepted whatever the result, so DMARC or a filter can decide. With `JSmtp.spf.rejectFail=true`, a `fail` is refused at MAIL FROM with `550 5.7.23 SPF validation failed:` followed by the domain's explanation (its `exp=` text).
- **Forged headers:** Received-SPF and Authentication-Results fields that claim to come from this server are removed.
- **DNS:** queries use the `parley-dns` resolver's DNS servers when `JSmtp.resolver=parley-dns` (or `parley-dns-iterative`). Otherwise they go to the servers in `/etc/resolv.conf` through parley-dns.
- **Turning it off:** set `JSmtp.spf.check=false`.

### DMARC (RFC 7489)

For mail from other servers, the server combines the SPF and DKIM results with the policy the From domain publishes at `_dmarc.<domain>`. The code is in `us.bringardner.parley.smtp.dmarc`.

- **Pass:** the message passes if a DKIM signature passed with a `d=` domain, or SPF passed with a domain, that is *aligned* with the From domain. Aligned means the same domain (strict, `adkim=s`/`aspf=s`), or the same organizational domain (relaxed, the default): `news.example.com` aligns with `example.com`.
- **Organizational domains** come from the Public Suffix List. A copy (`public_suffix_list.dat`, MPL 2.0, from publicsuffix.org) is included. Point `JSmtp.dmarc.publicSuffixList` at a newer download to replace it.
- **Policy lookup:** the record at `_dmarc.<From domain>`, else at `_dmarc.<organizational domain>`, where `sp=` applies to subdomains. A record whose `p=` is missing or invalid counts as `p=none` if it has a valid `rua=`; otherwise it is ignored. `pct=` sampling is honoured: mail outside the sample gets one step milder treatment.
- **Recording the result:** it is added to Authentication-Results, e.g. `dmarc=fail (p=reject dis=reject) header.from=example.org`. The results are `pass`, `fail`, `none` (no policy), `temperror` (DNS) or `permerror` (no From field, several From fields, or From addresses in more than one domain).
- **Enforcing:** with `JSmtp.dmarc.enforce=true`, `p=reject` is refused at the end of DATA with `550 5.7.1 Rejected by the DMARC policy of <domain>`. `p=quarantine` is delivered to the recipient's Junk mailbox: the IMAP `\Junk` mailbox, created if missing. Without it (the default) the result is only recorded.
- **DNS:** lookups use parley-dns, the same way as DKIM keys.
- **Turning it off:** set `JSmtp.dmarc.check=false`.

#### Reports

Domains ask for reports with `rua=` (aggregate) and `ruf=` (failure) in their DMARC record. Both kinds are off by default.

- **Aggregate reports** (`JSmtp.dmarc.aggregateReports=true`, RFC 7489 section 7.2):
  - Each evaluation is stored in `.dmarc-reports` under the maildrop root, so it survives restarts.
  - Every `JSmtp.dmarc.reportIntervalHours` (default 24), each domain gets one XML report.
  - Identical messages share a row, with a count. The `disposition` is what was actually done; a fail that wasn't enforced is marked `local_policy`, and a pct= downgrade `sampled_out`.
  - The XML is gzipped and mailed as `<org>!<domain>!<begin>!<end>.xml.gz`, with the subject `Report Domain: <domain> Submitter: <org> Report-ID: <id>`.
- **Failure reports** (`JSmtp.dmarc.failureReports=true`, section 7.3):
  - Sent at once in the Abuse Reporting Format (RFC 6591): a `message/feedback-report` part, plus the message's header (never its body).
  - Sent when the domain's `fo=` options call for one: `0` (default) when nothing passed aligned, `1` when either SPF or DKIM didn't pass aligned, `d` when a DKIM signature failed, `s` when SPF failed.
  - At most `JSmtp.dmarc.maxFailureReportsPerHour` (default 10) per domain. Never sent about a message that is itself a report.
- **Report addresses:** only `mailto:` URIs are supported, and their size limits (`!10m`) are honoured. An address outside the policy domain's organization is used only if its domain agrees to take the reports (a `v=DMARC1` TXT record at `<policy domain>._report._dmarc.<report domain>`, section 7.1).
- **Sending:** reports go out through the queue from `JSmtp.dmarc.reportEmail` (default `postmaster@<hostname>`). They are DKIM-signed if a key fits that domain. `JSmtp.dmarc.reportOrgName` (default the host name) names the reporter.

### ARC (RFC 8617)

Forwarding (an alias with members at other servers, a mailing list) breaks SPF, and changes made along the way break DKIM, so forwarded mail can fail DMARC at the next server. ARC lets each server that handles a message record what it found, in a chain of sealed ARC sets the next server can check. The code is in `us.bringardner.parley.smtp.dkim` (`ArcVerifier`, `ArcSealer`, `Arc`).

- **Validating:** for mail from other servers, the chain is checked: its structure, the newest ARC-Message-Signature and every ARC-Seal. The result goes in Authentication-Results, e.g. `arc=pass (as[2].d=lists.example.org as[1].d=example.com) smtp.remote-ip=192.0.2.1`; `arc=fail` comes with a `reason=`. Keys are found the same way as DKIM keys.
- **Trusted sealers:** with `JSmtp.dmarc.enforce=true`, mail that fails DMARC is still delivered normally when its chain passes and the newest seal is from a domain in `JSmtp.arc.trustedSealers` (organizational domains compared), as in section 7.2. The DMARC aggregate report marks this as `local_policy` with a comment naming the seals and the first hop's IP address (section 7.2.2).
- **Sealing:** when mail received from another server is forwarded to another server, an ARC set is added before it goes, once per message. The ARC-Authentication-Results copy our Authentication-Results, and the seal's `cv=` is our `arc=` result. Mail from our own users is DKIM-signed instead.
- **Keys:** sets are sealed with the DKIM key (`JSmtp.dkim.keys`) of `JSmtp.arc.domain` (default the host name), or of its closest parent domain: a key for `example.com` seals for `mx.example.com`. ARC defines only `rsa-sha256`, so an Ed25519 key doesn't seal; with no RSA key that fits, nothing is sealed.
- **Format:** tags are written in sorted order and long `b=` values in lines of 72 characters, like dkimpy, so the sets are byte-for-byte those of the reference implementation.
- **Turning it off:** set `JSmtp.arc.verify=false` or `JSmtp.arc.seal=false`.

### Configuration

| Property | Default | Meaning |
|---|---|---|
| `JSmtp.port` | 25 | Relay port (used by `main`) |
| `JSmtp.submissionPort` / `JSmtp.submissionsPort` | 587 / 0 | Submission ports started by `main` (0 = none); 465 uses implicit TLS |
| `JSmtp.root` | `JPop3.root`, else `/pop3` | Maildrop root, shared with POP3 and IMAP; the queue is `.smtp-queue` inside it |
| `JSmtp.hostname` | the local host name | Name in the greeting, Received headers and notifications |
| `JSmtp.domains` | the host name | Local domains, comma-separated |
| `JSmtp.relayNetworks` | none | Networks that may relay without AUTH, e.g. `127.0.0.1/32,10.0.0.0/8` |
| `JSmtp.requireTls` | false | AUTH (and MAIL on submission ports) only after STARTTLS |
| `JSmtp.maxMessageSize` | 52428800 | SIZE limit |
| `JSmtp.maxRecipients` | 100 | Recipients per message |
| `JSmtp.timeout` | 300000 ms | Idle session timeout (RFC 5321 requires at least 5 minutes) |
| `JSmtp.aliases`, `JSmtp.postmaster` | none, `postmaster` | Aliases file; user who receives postmaster mail |
| `JSmtp.relayHost`, `JSmtp.relayUser`, `JSmtp.relayPassword`, `JSmtp.relayTls` | none, none, none, `required` | Smart host |
| `JSmtp.resolver`, `JSmtp.dnsServers` | `jdk`, from `/etc/resolv.conf` | MX resolver: `jdk`, `parley-dns` or `parley-dns-iterative` (the older `bjldns` names still work); DNS servers for `parley-dns` |
| `JSmtp.preferIpv6` | false | With `parley-dns`: try mail hosts' IPv6 addresses before IPv4 (every host's addresses of both families are tried either way) |
| `JSmtp.tls` | `opportunistic` | STARTTLS to MX hosts: `none`, `opportunistic` or `required` |
| `JSmtp.queue.workers`, `JSmtp.queue.retry`, `JSmtp.queue.delayWarningHours`, `JSmtp.queue.maxAgeHours` | 4, `1,5,15,30,60,120`, 4, 120 | Queue settings |
| `JSmtp.dkim.keys` | none | DKIM signing keys: `domain:selector:keyfile`, comma-separated |
| `JSmtp.dkim.headers` | see above | Fields to sign, comma-separated (From is required) |
| `JSmtp.dkim.verify` | true | Verify DKIM signatures of incoming mail and add Authentication-Results |
| `JSmtp.spf.check` | true | Check SPF for incoming mail and add Received-SPF and Authentication-Results |
| `JSmtp.spf.rejectFail` | false | Refuse MAIL FROM when the SPF result is `fail` (550 5.7.23) |
| `JSmtp.dmarc.check` | true | Check DMARC for incoming mail and add the result to Authentication-Results |
| `JSmtp.dmarc.enforce` | false | Act on the policy: refuse `p=reject` mail (550 5.7.1), deliver `p=quarantine` mail to Junk |
| `JSmtp.dmarc.publicSuffixList` | the included copy | A newer `public_suffix_list.dat` for organizational domains |
| `JSmtp.dmarc.aggregateReports`, `JSmtp.dmarc.failureReports` | false, false | Send DMARC aggregate (`rua=`) and failure (`ruf=`) reports |
| `JSmtp.dmarc.reportEmail`, `JSmtp.dmarc.reportOrgName` | `postmaster@<hostname>`, the host name | The reports' sender address and reporting organization |
| `JSmtp.dmarc.reportIntervalHours`, `JSmtp.dmarc.maxFailureReportsPerHour` | 24, 10 | How often aggregate reports go out; failure reports per domain per hour |
| `JSmtp.arc.verify`, `JSmtp.arc.seal` | true, true | Validate the ARC chains of incoming mail; seal received mail that is forwarded (if a DKIM key fits the seal domain) |
| `JSmtp.arc.domain` | the host name | The `d=` of our ARC seals |
| `JSmtp.arc.trustedSealers` | none | Domains whose passing ARC chains override a DMARC failure, comma-separated |
| `SmtpServer.KeyStoreName`, `SmtpServer.KeyStorePassword`, `SmtpServer.KeyStoreType` | none | Key store for STARTTLS and port 465 |

### Not included

- **Spam filtering:** DKIM, SPF, DMARC (with reports) and ARC are supported, but there is no spam filtering. DMARC reports only go to `mailto:` addresses.
- **Envelope sender:** authenticated users may use any address as the sender; it isn't checked against the login.
- **Optional extensions:** REQUIRETLS, MT-PRIORITY and DELIVERBY aren't implemented.

### Testing

`TestSmtpServer` runs two servers on real sockets. Server A (`a.test`) relays to server B (`b.test`) through a test MX resolver. The tests cover:

- local delivery, aliases, `postmaster` and relay refusal;
- submission with STARTTLS, AUTH PLAIN and AUTH LOGIN;
- bounces with DSN parameters, delay and expiry notices;
- PIPELINING, BDAT and BINARYMIME, smuggling and loop protection;
- SMTPUTF8;
- a queue that survives a restart;
- a 70 MB message under the 64 MB test heap.

`TestDkim` checks signing and verification against the RFC 8463 example message (RSA and Ed25519) and the RFC 6376 canonicalization examples. `TestDkimSmtp` runs a signing server that relays to a verifying one, and covers forged Authentication-Results, signed bounces, and mail queued from code. `TestParleyDnsMxResolver` looks a DKIM key up from a parley-dns server.

`TestSpfSuite` runs the openspf.org RFC 7208 test suite (`src/test/resources/spf/rfc7208-tests.yml`, from pyspf), and all 203 cases pass. `TestSpfSmtp` covers how results are recorded, rejection, the HELO check for bounces, and forged headers. `TestParleyDnsMxResolver` runs SPF checks against a parley-dns server.

`TestDmarc` runs the publicsuffix.org test file against the included Public Suffix List. It also covers record parsing, strict and relaxed alignment, `sp=`, `pct=` sampling, DNS errors and bad From fields. `TestDmarcSmtp` covers an aligned pass through a signing relay, a forged From (recorded, or refused when enforcing), quarantine to Junk, and an aligned SPF pass.

`TestDmarcReports` covers aggregate reports, validated against the RFC 7489 schema (`src/test/resources/dmarc/rfc7489.xsd`, repaired as its header explains). It also covers row counts, restarts, report-address permission and size limits, the ARF failure report, `fo=` options, rate limits, and not reporting on reports. `TestDmarcSmtp` also follows both kinds of report through the queue to a mailbox.

`TestArcSuite` runs the ValiMail ARC test suite (`src/test/resources/arc/`, MIT licence, from github.com/ValiMail/arc_test_suite). All 171 validation cases pass. One case, `ams_fields_c_na`, is checked as `fail` rather than the suite's `pass`: RFC 8617 makes `c=` default to `simple/simple`, as in DKIM, and the suite assumes `relaxed`. In the signing cases, every ARC-Authentication-Results and ARC-Message-Signature field matches exactly. The ARC-Seal `b=` values the suite expects are out of date: its own later messages carry the seals for the same input, and ours match those byte for byte. Every set we make is also validated. `TestArcSmtp` forwards mail through an alias on one server to another. It covers the added set, `arc=pass`, a DMARC failure overridden for a trusted sealer (with its aggregate report row), and a rejection when the sealer isn't trusted.

`TestParleyDnsMxResolver` starts a real parley-dns `DnsServer` on a free port on 127.0.0.1, with zone files written to a temp directory (`mx.test` with two MX hosts, `implicit.test` with only an A record, `nullmx.test` with a null MX). It checks `ParleyDnsMxResolver` against it, including a host with both A and AAAA records and an IPv6-only host (`v6only.test`), and relays messages between two SMTP servers using the MX hosts it finds: over IPv4, over IPv6 (`::1`), and from an unreachable IPv6 address to the host's IPv4 address. The IPv6 relay test is skipped on machines without an IPv6 loopback.

Python's `smtplib` (with `starttls()` and `login()`) works with the server.
