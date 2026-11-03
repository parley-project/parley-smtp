package us.bringardner.parley.smtp.server;

import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.mail.server.AbstractMailServer;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;


import us.bringardner.parley.core.util.AddressMatcher;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.mail.Message;
import us.bringardner.parley.net.IProcessor;
import us.bringardner.parley.net.IProcessorFactory;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.SMTP;
import us.bringardner.parley.smtp.dkim.Dkim;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.Arc;
import us.bringardner.parley.smtp.dmarc.Dmarc;
import us.bringardner.parley.smtp.dmarc.DmarcReporter;
import us.bringardner.parley.smtp.dmarc.PublicSuffixList;
import us.bringardner.parley.smtp.abuse.ConnectionChecks;
import us.bringardner.parley.smtp.spf.Spf;
import us.bringardner.parley.smtp.queue.ParleyDnsMxResolver;
import us.bringardner.parley.smtp.queue.DeliveryConfig;
import us.bringardner.parley.smtp.queue.MailQueue;
import us.bringardner.parley.smtp.queue.QueueEntry;
import us.bringardner.parley.smtp.queue.QueueHistory;

/**
 * An SMTP server (RFC 5321, following draft-ietf-emailcore-rfc5321bis) and mail
 * transfer agent, built like FtpServer in parley-ftp and the POP3 and IMAP
 * servers: an {@link SmtpRequestProcessor} runs each session, with one command
 * class per SMTP command from {@link SmtpCommandFactory}.
 * <p>
 * Accepted mail goes into a persistent {@link MailQueue} under the maildrop root
 * (shared with POP3 and IMAP). Mail for the local domains is delivered to the
 * users' INBOXes; other mail is relayed to the domain's MX hosts (or a smart
 * host), but only for authenticated users or trusted networks.
 * <p>
 * One SmtpServer listens on one port, and is written as if it were the only server: it reads only
 * its own settings, under its prefix ({@value #SMTP_PREFIX}, {@value #SUBMISSION_PREFIX} or
 * {@value #SUBMISSIONS_PREFIX}), from its configuration (the system
 * properties for a server made by code). Whether it is a relay or a submission server comes from how
 * it is made ({@link #SmtpServer(int, String, boolean, boolean)}, {@link #submissionServer(boolean)}).
 * There is no relay with implicit TLS: RFC 8314's implicit TLS is submission's, and the relay is
 * SMTP with STARTTLS.
 * <p>
 * Its own settings are about its port: {@code hostname} (required: the greeting and Received
 * headers), {@code requireTls}, {@code relayNetworks}, {@code maxMessageSize}, {@code maxRecipients},
 * {@code timeout}, {@code maxHops}, the checks of incoming mail ({@code dkim.verify},
 * {@code spf.check}, {@code spf.rejectFail}, {@code dmarc.check}, {@code dmarc.enforce},
 * {@code dmarc.publicSuffixList}, {@code arc.verify}), the checks of the client before any mail
 * ({@code dnsbl.zones}, {@code rdns.require}, {@code helo.check}, {@code pregreet.delay},
 * {@code rate.connectionsPerMinute}, {@code rate.maxConcurrent}, {@code rate.messagesPerMinute},
 * {@code rate.recipientsPerMinute}, {@code checks.logOnly}: see {@link ConnectionChecks}; all off
 * by default, and skipped for clients that may relay) and where its queue is ({@value #QUEUE},
 * default {@value #QUEUE_DIRECTORY} under the maildrop root).
 * <p>
 * The queue is a shared asset and carries its own settings ({@link MailQueue#SETTINGS_FILE} in its
 * directory): how its mail is delivered, read by every server that uses it. A queue without them
 * isn't used, and the server doesn't start. Servers given the same queue share it through the
 * store's locks (in one JVM or several), so the store's sharing must allow them.
 */
public class SmtpServer extends AbstractMailServer implements SMTP {


	public static final String SMTP_NAME = "JSmtp";
	/** The prefix of the properties of an SMTP relay server (port 25). */
	public static final String SMTP_PREFIX = "parley.mail.smtp";
	/** The prefix of the properties of a submission server (RFC 6409, port 587). */
	public static final String SUBMISSION_PREFIX = "parley.mail.submission";
	/** The prefix of the properties of a submission server with implicit TLS (RFC 8314, port 465). */
	public static final String SUBMISSIONS_PREFIX = "parley.mail.submissions";
	/** A settings file for the servers' configuration (the file its main reads, or a launcher's). */
	public static final String CONFIG_PROP = SMTP_PREFIX + ".configFile";
	/** The maildrop root, shared with POP3 and IMAP. */
	public static final String ROOT_PROP = MAIL_ROOT_PROP;
	public static final String FILE_SOURCE_PROP = MAIL_FILE_SOURCE_PROP;
	/** The default queue: a directory of this name under the maildrop root */
	public static final String QUEUE_DIRECTORY = ".smtp-queue";
	/** Server setting (after its prefix): its queue, a directory under the maildrop root (default {@value #QUEUE_DIRECTORY}) */
	public static final String QUEUE = "queue";
	/** Where DMARC aggregate report data waits to be sent, under the maildrop root. */
	public static final String DMARC_REPORT_DIRECTORY = ".dmarc-reports";
	public static final long DEFAULT_MAX_MESSAGE_SIZE = 50L * 1024 * 1024;

	private volatile String hostname;
	private volatile boolean submission;
	private volatile long maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;
	private volatile int maxRecipients = 100;
	private volatile int timeout = 5 * 60 * 1000;
	private volatile int maxHops = 100;
	private final ConnectionChecks connectionChecks = new ConnectionChecks();
	private final us.bringardner.parley.smtp.spam.Spam spam = new us.bringardner.parley.smtp.spam.Spam();
	/** this server's queue: a directory under the maildrop root */
	private volatile String queueLocation = QUEUE_DIRECTORY;
	//  Replaced (not changed) when a network is added, so isRelayAllowed needs no lock
	private volatile AddressMatcher relayNetworks = AddressMatcher.NONE;

	private final DeliveryConfig deliveryConfig = new DeliveryConfig();
	private MailQueue queue;
	private boolean ownsQueue;
	/** the history of the queue this server made, or null */
	private QueueHistory queueHistory;
	private boolean queueStarted;

	/**
	 * A relay (port 25's server).
	 *
	 * @param secure must be false: there is no relay with implicit TLS
	 *               ({@link #submissionServer(boolean)} makes one with it)
	 * @throws IllegalArgumentException when secure is true
	 */
	public SmtpServer(int port, String name, boolean secure) {
		this(port, name, secure, false);
	}

	/**
	 * @param secure     implicit TLS, only for a submission server (RFC 8314)
	 * @param submission a submission server (RFC 6409: AUTH required), reading its settings with
	 *                   {@value #SUBMISSION_PREFIX} ({@value #SUBMISSIONS_PREFIX} with implicit TLS)
	 * @throws IllegalArgumentException for a relay with implicit TLS
	 */
	public SmtpServer(int port, String name, boolean secure, boolean submission) {
		super(port, name, prefixOf(secure, submission), secure);
		this.submission = submission;
		initMe();
		finishInit();
	}

	/** The prefix of a server's settings */
	static String prefixOf(boolean secure, boolean submission) {
		if (submission) {
			return secure ? SUBMISSIONS_PREFIX : SUBMISSION_PREFIX;
		}
		if (secure) {
			throw new IllegalArgumentException(NO_IMPLICIT_TLS_RELAY);
		}
		return SMTP_PREFIX;
	}

	static final String NO_IMPLICIT_TLS_RELAY = "There is no SMTP relay with implicit TLS; implicit TLS is for a submission server (submissionServer(true))";

	@Override
	protected String getRootProperty() {
		return ROOT_PROP;
	}

	public SmtpServer() {
		this(SMTP_PORT, SMTP_NAME, false);
	}

	/** A submission server (RFC 6409): port 587, or 465 with implicit TLS (RFC 8314). */
	public static SmtpServer submissionServer(boolean implicitTls) {
		return new SmtpServer(implicitTls ? SUBMISSIONS_PORT : SUBMISSION_PORT, SMTP_NAME, implicitTls, true);
	}

	/**
	 * Run the relay (parley.mail.smtp.port, default 25), submission (parley.mail.submission.port,
	 * default 587) and, when there is a TLS key store, submission with implicit TLS
	 * (parley.mail.submissions.port, default 465) in this process until it is stopped, with
	 * parley-net's ServerMain.run: the settings are parley-smtp.properties in the settings folder (or
	 * the file parley.mail.smtp.configFile names) and the command line, read as system properties,
	 * each server under its prefix. (The mail suite's servers are run by parley-mail-admin's launcher.)
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.run("SmtpServer", args, CONFIG_PROP, "parley-smtp.properties", () -> {
			java.util.List<ServerMain.Service> ret = new java.util.ArrayList<>();
			{
				int p = standalonePort(SMTP_PREFIX, SMTP_PORT);
				ret.add(us.bringardner.parley.mail.server.MailServerMain.service(new SmtpServer(p, SMTP_NAME, false, false), "SMTP server", "smtp"));
			}
			{
				int p = standalonePort(SUBMISSION_PREFIX, SUBMISSION_PORT);
				ret.add(us.bringardner.parley.mail.server.MailServerMain.service(new SmtpServer(p, SMTP_NAME, false, true), "Submission server", "submission"));
			}
			if (hasKeyStore(SUBMISSIONS_PREFIX)) {
				int p = standalonePort(SUBMISSIONS_PREFIX, SUBMISSIONS_PORT);
				ret.add(us.bringardner.parley.mail.server.MailServerMain.service(new SmtpServer(p, SMTP_NAME, true, true), "Submission server (implicit TLS)", "submissions"));
			} else {
				System.err.println("Warning: Submission server (implicit TLS) is skipped: no TLS key store (set " + MAIL_TLS_KEY_STORE_PROP + " or " + SUBMISSIONS_PREFIX + ".keyStoreName)");
			}
			return ret;
		});
	}

	/** A server's port in a standalone process: {@code <prefix>.port}, else its standard port */
	private static int standalonePort(String prefix, int standard) {
		String v = System.getProperty(prefix + ".port");
		return v == null || v.trim().isEmpty() ? standard : Integer.parseInt(v.trim());
	}

	/** A TLS key store for this server in a standalone process: the suite's, or its own */
	private static boolean hasKeyStore(String prefix) {
		String a = System.getProperty(MAIL_TLS_KEY_STORE_PROP);
		String b = System.getProperty(prefix + ".keyStoreName");
		return (a != null && !a.trim().isEmpty()) || (b != null && !b.trim().isEmpty());
	}

	private void initMe() {
		setName("SmtpServer");
		setProcessorFactory(new IProcessorFactory() {
			@Override
			public IProcessor getProcessor() {
				SmtpRequestProcessor ret = new SmtpRequestProcessor();
				ret.getLogger().setLevel(SmtpServer.this.getLogger().getLevel());
				return ret;
			}
		});
		// sessions read the socket themselves and time out on their own
		setMaxIdleConnection(Long.MAX_VALUE / 2);

		readServerSettings();

		IAccessControlList acl = getAccessControl();
		if (acl == null) {
			logInfo("No access control is configured for " + getName() + "; no one can log in and no local users exist");
		}
	}

	// ------------------------------------------------------------------ settings

	/** A setting of this server (after its prefix), or null */
	private String setting(String name) {
		String v = getProperty(propertyName(name));
		return v == null || v.trim().isEmpty() ? null : v.trim();
	}

	private boolean setting(String name, boolean defaultValue) {
		String v = setting(name);
		return v == null ? defaultValue : Boolean.parseBoolean(v);
	}

	private long setting(String name, long defaultValue) {
		String v = setting(name);
		return v == null ? defaultValue : Long.parseLong(v);
	}

	private int setting(String name, int defaultValue) {
		String v = setting(name);
		return v == null ? defaultValue : Integer.parseInt(v);
	}

	/** A duration setting of this server ({@code 30s}, {@code 5m}; a bare number is ms), in ms */
	private long durationSetting(String name, long defaultMillis) {
		return getDuration(propertyName(name), defaultMillis);
	}

	/**
	 * Read this server's own settings (about its port), under its prefix: again when the prefix
	 * changes ({@link #setSubmission(boolean)}).
	 */
	private void readServerSettings() {
		setRequireTls(setting("requireTls", false));
		initMaildropRoot(FILE_SOURCE_PROP, null, ROOT_PROP, null, null, null);
		hostname = setting("hostname"); // required: start() says so
		maxMessageSize = setting("maxMessageSize", DEFAULT_MAX_MESSAGE_SIZE);
		maxRecipients = setting("maxRecipients", 100);
		timeout = us.bringardner.parley.core.util.Durations.toIntMillis(durationSetting("timeout", 5 * 60 * 1000));
		maxHops = setting("maxHops", 100);
		String networks = setting("relayNetworks");
		relayNetworks = networks == null ? AddressMatcher.NONE : AddressMatcher.parse(networks);
		String q = setting(QUEUE);
		queueLocation = q == null ? QUEUE_DIRECTORY : q;

		// the checks of incoming mail
		DeliveryConfig c = deliveryConfig;
		c.getDkim().setVerify(setting("dkim.verify", true));
		Spf spf = c.getSpf();
		spf.setCheck(setting("spf.check", true));
		spf.setRejectFail(setting("spf.rejectFail", false));
		Dmarc dmarc = c.getDmarc();
		dmarc.setCheck(setting("dmarc.check", true));
		dmarc.setEnforce(setting("dmarc.enforce", false));
		String psl = setting("dmarc.publicSuffixList");
		if (psl != null) {
			try {
				dmarc.setPublicSuffixList(PublicSuffixList.load(new File(psl)));
			} catch (IOException e) {
				logError("Can't read the public suffix list " + psl + "; using the included copy", e);
			}
		}
		c.getArc().setVerify(setting("arc.verify", true));

		// the checks of the client
		String zones = setting("dnsbl.zones");
		connectionChecks.getDnsbl().setZones(zones == null ? new ArrayList<>() : java.util.Arrays.asList(zones.split("[,\\s]+")));
		connectionChecks.setLogOnly(setting("checks.logOnly", false));
		connectionChecks.setRequireReverseDns(setting("rdns.require", false));
		connectionChecks.setCheckHelo(setting("helo.check", false));
		connectionChecks.setPregreetMillis(durationSetting("pregreet.delay", 0L));
		connectionChecks.setMaxConnectionsPerMinute(setting("rate.connectionsPerMinute", 0));
		connectionChecks.setMaxConcurrentPerAddress(setting("rate.maxConcurrent", 0));
		connectionChecks.setMaxMessagesPerMinute(setting("rate.messagesPerMinute", 0));
		connectionChecks.setMaxRecipientsPerMinute(setting("rate.recipientsPerMinute", 0));

		// the spam provider (spam.*): the provider and its settings are this server's, the per-domain overrides the queue's
		spam.setLog((m, e) -> {
			if (e == null) {
				logInfo(m);
			} else {
				logError(m, e);
			}
		});
		try {
			spam.configure(n -> setting("spam." + n));
		} catch (RuntimeException e) {
			logError("Wrong spam settings (" + propertyName("spam.*") + "): " + e.getMessage() + "; spam checking keeps its earlier settings", e);
		}
	}

	/** SMTP's id for its own credential settings, {@code parley.credentials.smtp.*} */
	public static final String CREDENTIALS_ID = "smtp";

	/** The queue's 1.x / earlier 2.0.0 names, and what they are now (a warning names the new one) */
	private static final java.util.Map<String, String> RENAMED_QUEUE_SETTINGS;
	static {
		java.util.Map<String, String> m = new java.util.LinkedHashMap<>();
		m.put("relayHost", "smartHost (and smartHost.port)");
		m.put("relayUser", "smartHost.user");
		m.put("relayPassword", "smartHost.password");
		m.put("relayAuth", "smartHost.auth");
		m.put("relayTls", "smartHost.tls");
		m.put("maxAgeHours", "maxAge, a duration (5d)");
		m.put("delayWarningHours", "delayWarning, a duration (4h)");
		m.put("dmarc.reportIntervalHours", "dmarc.reportInterval, a duration (24h)");
		RENAMED_QUEUE_SETTINGS = java.util.Collections.unmodifiableMap(m);
	}

	/** A queue setting, or null */
	private static String queueSetting(java.util.Properties q, String name) {
		String v = q.getProperty(name);
		return v == null || v.trim().isEmpty() ? null : v.trim();
	}

	/**
	 * Use the queue's own settings ({@link MailQueue#SETTINGS_FILE}): how its mail is delivered.
	 * Every server that uses the queue reads the same ones.
	 *
	 * @throws IOException if a required one is missing (hostname, domains) or one is wrong
	 */
	private void useQueueSettings(java.util.Properties q, FileSource queueDir) throws IOException {
		String where = " (" + queueDir.getAbsolutePath() + "/" + MailQueue.SETTINGS_FILE + ")";
		checkQueueSettings(q, where); // before anything is changed: a refused queue leaves nothing behind
		try {
			applyQueueSettings(q, where);
		} catch (RuntimeException e) {
			throw new IOException("Wrong mail queue settings" + where + ": " + e.getMessage(), e);
		}
	}

	/** The queue's settings that must be there, or be right, before any is used */
	private void checkQueueSettings(java.util.Properties q, String where) throws IOException {
		if (queueSetting(q, "hostname") == null) {
			throw new IOException("The mail queue's hostname isn't set" + where);
		}
		if (queueSetting(q, "domains") == null) {
			throw new IOException("The mail queue's domains aren't set" + where);
		}
		String pw = queueSetting(q, "smartHost.password");
		if (pw != null && !us.bringardner.parley.files.credentials.CredentialRef.isReference(pw)) {
			throw new IOException("The mail queue's smartHost.password must name where the password is kept (@keychain:..., @file:..., @env:...), not hold it"
					+ where);
		}
		String smartHost = queueSetting(q, "smartHost");
		if (smartHost != null && smartHost.matches("[^:\\[\\]]+:\\d+")) {
			throw new IOException("The mail queue's smartHost is the host only (" + smartHost + "): put the port in smartHost.port" + where);
		}
		for (java.util.Map.Entry<String, String> e : RENAMED_QUEUE_SETTINGS.entrySet()) {
			if (queueSetting(q, e.getKey()) != null) {
				logError("The mail queue's " + e.getKey() + where + " is no longer read: it is " + e.getValue() + " in 2.0.0");
			}
		}
		DmarcReporter reporter = deliveryConfig.getDmarc().getReporter();
		String agg = queueSetting(q, "dmarc.aggregateReports");
		String fail = queueSetting(q, "dmarc.failureReports");
		boolean reports = (agg != null ? Boolean.parseBoolean(agg) : reporter.isAggregate()) || (fail != null ? Boolean.parseBoolean(fail) : reporter.isFailure());
		String org = queueSetting(q, "dmarc.reportOrgName");
		String email = queueSetting(q, "dmarc.reportEmail");
		// no default from another setting: reports say who sends them only when told
		boolean noOrg = org == null && (reporter.getOrgName() == null || reporter.getOrgName().isEmpty() || "localhost".equals(reporter.getOrgName()));
		boolean noEmail = email == null && (reporter.getEmail() == null || reporter.getEmail().endsWith("@localhost"));
		if (reports && (noOrg || noEmail)) {
			throw new IOException("DMARC reports need dmarc.reportOrgName and dmarc.reportEmail" + where);
		}
	}

	private void applyQueueSettings(java.util.Properties q, String where) throws IOException {
		DeliveryConfig c = deliveryConfig;
		String host = queueSetting(q, "hostname");
		c.setHostname(host);
		for (String d : queueSetting(q, "domains").split(",")) {
			if (!d.trim().isEmpty()) {
				c.addLocalDomain(d.trim());
			}
		}
		String tmp = queueSetting(q, "postmaster");
		if (tmp != null) {
			c.setPostmaster(tmp);
		}
		String aliases = queueSetting(q, "aliases");
		if (aliases != null) {
			try (InputStream in = getFileSourceFactory().createFileSource(aliases).getInputStream()) {
				c.loadAliases(new String(in.readAllBytes(), StandardCharsets.UTF_8));
			} catch (IOException e) {
				logError("Can't read the aliases file " + aliases, e);
			}
		}
		tmp = queueSetting(q, "smartHost");
		if (tmp != null) {
			c.setRelayHost(tmp);
			String port = queueSetting(q, "smartHost.port");
			if (port != null) {
				c.setRelayPort(Integer.parseInt(port));
			}
		}
		c.setRelayUser(queueSetting(q, "smartHost.user"));
		tmp = queueSetting(q, "smartHost.password");
		if (tmp != null) {
			// a secret: the settings name where it is kept (@keychain:..., @file:..., @env:...), never the password;
			// resolved as SMTP's (parley.credentials.smtp.*)
			char[] secret = us.bringardner.parley.files.credentials.Credentials.secret(tmp,
					new us.bringardner.parley.files.credentials.CredentialRequest(CREDENTIALS_ID, "smartHost.password",
							c.getRelayHost(), c.getRelayUser()));
			c.setRelayPassword(new String(secret));
			java.util.Arrays.fill(secret, '\0');
		}
		tmp = queueSetting(q, "smartHost.auth");
		if (tmp != null) {
			c.setRelayAuthMechanisms(java.util.Arrays.asList(tmp.split("\\s*,\\s*")));
		}
		tmp = queueSetting(q, "smartHost.tls");
		if (tmp != null) {
			c.setRelayTlsMode(DeliveryConfig.TlsMode.valueOf(tmp.toUpperCase(Locale.ROOT)));
		}
		c.setSpamDomains(us.bringardner.parley.smtp.spam.Spam.parseDomains(queueSetting(q, "spam.domains") == null ? "" : queueSetting(q, "spam.domains")));
		tmp = queueSetting(q, "tls");
		if (tmp != null) {
			c.setTlsMode(DeliveryConfig.TlsMode.valueOf(tmp.toUpperCase(Locale.ROOT)));
		}
		tmp = queueSetting(q, "remotePort");
		if (tmp != null) {
			c.setRemotePort(Integer.parseInt(tmp));
		}
		tmp = q.getProperty("resolver", "").trim().toLowerCase(Locale.ROOT);
		try {
			switch (tmp) {
			case "parley-dns":
			case "bjldns": { // older name, still accepted
				String list = queueSetting(q, "dnsServers");
				ParleyDnsMxResolver r = new ParleyDnsMxResolver(list == null ? ParleyDnsMxResolver.systemServers() : ParleyDnsMxResolver.parseServers(list));
				r.setPreferIpv6(Boolean.parseBoolean(q.getProperty("preferIpv6", "false").trim()));
				c.setResolver(r);
				break;
			}
			case "parley-dns-iterative":
			case "bjldns-iterative": // older name, still accepted
				c.setResolver(ParleyDnsMxResolver.iterative());
				break;
			case "jdk":
			case "": // not set: the resolver as it is (the JDK's, or one set by code)
				break;
			default:
				logInfo("Unknown resolver '" + tmp + "'" + where + "; using the JDK resolver");
			}
		} catch (IOException | RuntimeException e) {
			logError("Can't set up the " + tmp + " resolver; using the JDK resolver", e);
		}
		if (c.getResolver() instanceof ParleyDnsMxResolver) {
			// the same DNS servers as for MX lookups, for the checks of incoming mail too
			ParleyDnsMxResolver r = (ParleyDnsMxResolver) c.getResolver();
			c.getDkim().setLookup(r::txt);
			c.getSpf().setDns(r::records);
			c.getDmarc().setDns(r::txt);
		}
		tmp = queueSetting(q, "dkim.keys");
		if (tmp != null) {
			try {
				c.getDkim().addSigners(tmp, queueSetting(q, "dkim.headers"));
			} catch (IOException | GeneralSecurityException | RuntimeException e) {
				logError("Can't load the DKIM keys (dkim.keys" + where + "); mail is sent unsigned", e);
			}
		}
		tmp = queueSetting(q, "dkim.shared");
		c.getDkim().setShared(tmp);
		if (tmp != null && c.getDkim().sharedSignerFor(tmp) == null) {
			logError("The shared DKIM key's domain " + tmp + " has no key in dkim.keys" + where
					+ "; mail from local domains without a key of their own is sent unsigned");
		}
		Arc arc = c.getArc();
		tmp = queueSetting(q, "arc.seal");
		if (tmp != null) {
			arc.setSeal(Boolean.parseBoolean(tmp));
		}
		tmp = queueSetting(q, "arc.domain");
		if (tmp != null) {
			arc.setDomain(tmp);
		}
		tmp = queueSetting(q, "arc.trustedSealers");
		if (tmp != null) {
			arc.addTrustedSealers(tmp);
		}
		DmarcReporter reporter = c.getDmarc().getReporter();
		tmp = queueSetting(q, "dmarc.aggregateReports");
		if (tmp != null) {
			reporter.setAggregate(Boolean.parseBoolean(tmp));
		}
		tmp = queueSetting(q, "dmarc.failureReports");
		if (tmp != null) {
			reporter.setFailure(Boolean.parseBoolean(tmp));
		}
		reporter.setHostname(host);
		String org = queueSetting(q, "dmarc.reportOrgName");
		String email = queueSetting(q, "dmarc.reportEmail");
		if (org != null) {
			reporter.setOrgName(org);
		}
		if (email != null) {
			reporter.setEmail(email);
		}
		tmp = queueSetting(q, "dmarc.reportInterval");
		if (tmp != null) {
			reporter.setIntervalMillis(queueDuration("dmarc.reportInterval", tmp));
		}
		tmp = queueSetting(q, "dmarc.maxFailureReportsPerHour");
		if (tmp != null) {
			reporter.setMaxFailurePerHour(Integer.parseInt(tmp));
		}
		tmp = queueSetting(q, "workers");
		if (tmp != null) {
			c.setWorkers(Integer.parseInt(tmp));
		}
		tmp = queueSetting(q, "retry");
		if (tmp != null) {
			long[] schedule;
			try {
				schedule = us.bringardner.parley.core.util.Durations.parseList(tmp);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("retry=" + tmp + ": " + e.getMessage(), e);
			}
			for (long r : schedule) {
				if (r < 1000) {
					// 1.x's retry was in minutes; a bare number is ms now
					logError("The mail queue's retry=" + tmp + where + " has a wait under a second: a number without a unit is ms (1m,5m,15m)");
					break;
				}
			}
			c.setRetrySchedule(schedule);
		}
		tmp = queueSetting(q, "maxAge");
		if (tmp != null) {
			c.setMaxAge(queueDuration("maxAge", tmp));
		}
		tmp = queueSetting(q, "delayWarning");
		if (tmp != null) {
			c.setDelayWarning(queueDuration("delayWarning", tmp));
		}
	}

	/** A duration in the queue's settings ({@code 5d}, {@code 4h}; a bare number is ms) */
	private static long queueDuration(String name, String value) {
		try {
			return us.bringardner.parley.core.util.Durations.parse(value);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException(name + "=" + value + ": " + e.getMessage(), e);
		}
	}

	/**
	 * Read the queue's domains, aliases file, DKIM keys and spam settings again ({@link MailQueue#reload()}) and use
	 * them at once; a mail being received or delivered sees the old ones or the new ones. Every one is
	 * read before any is used, so nothing changes when one can't be read.
	 */
	private String reloadQueueSettings(FileSource dir) throws IOException {
		String where = " (" + dir.getAbsolutePath() + "/" + MailQueue.SETTINGS_FILE + ")";
		java.util.Properties q = MailQueue.readSettings(dir);
		String domains = queueSetting(q, "domains");
		if (domains == null) {
			throw new IOException("The mail queue's domains aren't set" + where);
		}
		List<String> domainList = new ArrayList<>();
		for (String d : domains.split(",")) {
			if (!d.trim().isEmpty()) {
				domainList.add(d.trim());
			}
		}
		java.util.Map<String, List<String>> aliasMap = java.util.Collections.emptyMap();
		String aliases = queueSetting(q, "aliases");
		if (aliases != null) {
			try (InputStream in = getFileSourceFactory().createFileSource(aliases).getInputStream()) {
				aliasMap = DeliveryConfig.parseAliases(new String(in.readAllBytes(), StandardCharsets.UTF_8));
			} catch (IOException e) {
				throw new IOException("Can't read the aliases file " + aliases + ": " + e.getMessage(), e);
			}
		}
		List<DkimSigner> signers = java.util.Collections.emptyList();
		String keys = queueSetting(q, "dkim.keys");
		if (keys != null) {
			try {
				signers = Dkim.parseSigners(keys, queueSetting(q, "dkim.headers"));
			} catch (IOException | GeneralSecurityException | RuntimeException e) {
				throw new IOException("Can't load the DKIM keys (dkim.keys" + where + "): " + e.getMessage(), e);
			}
		}
		String shared = queueSetting(q, "dkim.shared");
		List<String> signed = new ArrayList<>();
		for (DkimSigner s : signers) {
			signed.add(s.getDomain());
		}
		if (shared != null && !signed.contains(shared.toLowerCase(Locale.ROOT))) {
			throw new IOException("The shared DKIM key's domain " + shared + " has no key in dkim.keys" + where);
		}
		java.util.Map<String, String> spamDomains;
		try {
			spamDomains = us.bringardner.parley.smtp.spam.Spam.parseDomains(queueSetting(q, "spam.domains") == null ? "" : queueSetting(q, "spam.domains")); // wrong settings change nothing
		} catch (RuntimeException e) {
			throw new IOException("Wrong spam settings" + where + ": " + e.getMessage(), e);
		}
		DeliveryConfig c = getQueue().getConfig();
		// the aliases and keys before the domains: a new domain is local only once they are there
		c.setAliases(aliasMap);
		c.setSpamDomains(spamDomains);
		c.getDkim().setSigners(signers);
		c.getDkim().setShared(shared);
		c.setLocalDomains(domainList);
		String msg = "Mail queue settings read again" + where + ": domains " + c.getLocalDomains() + ", " + aliasMap.size()
				+ " aliases, DKIM keys for " + signed + (shared == null ? "" : ", shared key " + shared) + ", spam overrides for " + spamDomains.size() + " domains";
		logInfo(msg);
		return msg;
	}

	/** The queue's directory: {@link #QUEUE} under the maildrop root */
	private FileSource queueDirectory(FileSource root) throws IOException {
		String q = queueLocation.replace('\\', '/');
		FileSource dir = root;
		for (String seg : q.split("/")) {
			if (seg.isEmpty() || seg.equals(".")) {
				continue;
			}
			if (seg.equals("..")) {
				throw new IOException("The queue (" + propertyName(QUEUE) + "=" + queueLocation + ") must be under the maildrop root");
			}
			dir = dir.getChild(seg);
		}
		if (dir == root) {
			throw new IOException("The queue (" + propertyName(QUEUE) + ") can't be the maildrop root itself");
		}
		return dir;
	}

	/** Refuse to start without a hostname (it has no default) */
	@Override
	public synchronized void start() {
		if (hostname == null) {
			IOException err = new IOException("The hostname isn't set (" + propertyName("hostname") + ")");
			logError("Can't start " + getName() + ": " + err.getMessage(), err);
			throw new java.io.UncheckedIOException(err);
		}
		super.start();
	}

	// ------------------------------------------------------------------ life cycle

	/** The queue starts once the store is claimed (so it never delivers from a store another server owns). */
	@Override
	protected void storeClaimed() throws IOException {
		try {
			startQueue();
		} catch (IOException e) {
			logError("Can't start the mail queue", e);
			throw e;
		}
	}

	private synchronized void startQueue() throws IOException {
		if (queueStarted) {
			return;
		}
		MailQueue q = getQueue();
		if (ownsQueue) {
			// a list the server made from its provider setting is closed when it stops and made
			// again at the next start: local delivery uses the one in use now
			deliveryConfig.setAccessControl(getAccessControl());
		}
		q.start();
		queueStarted = true;
		startDmarcReports();
	}

	/** Start the DMARC reporter (reports are kept in .dmarc-reports under the maildrop root). */
	private void startDmarcReports() {
		Dmarc dmarc = getDeliveryConfig().getDmarc();
		DmarcReporter r = dmarc.getReporter();
		if (!r.isAggregate() && !r.isFailure()) {
			return;
		}
		try {
			MailQueue q = getQueue();
			r.start(getMaildropRoot().getChild(DMARC_REPORT_DIRECTORY), (from, to, message) -> {
				List<MailAddress> rcpts = new ArrayList<>();
				for (String a : to) {
					rcpts.add(MailAddress.parse(a, true));
				}
				q.enqueue(MailAddress.parse(from, true), rcpts, new java.io.ByteArrayInputStream(message), false);
			}, dmarc.getDns(), dmarc.getPublicSuffixList());
		} catch (IOException | RuntimeException e) {
			logError("Can't start the DMARC reporter", e);
		}
	}

	/** The queue stops after connections and before the store claim is given up. */
	@Override
	protected synchronized void releasingStore() {
		if (queueStarted) {
			queue.stop();
			queueStarted = false;
			if (ownsQueue && queueHistory != null) {
				queueHistory.close();
			}
			if (!queue.isRunning()) {
				// the last server using the queue (a shared queue's other servers still need the reporter)
				getDeliveryConfig().getDmarc().getReporter().stop();
			}
		}
	}

	// ------------------------------------------------------------------ mail

	/** Routing, local domains, aliases and retry settings of the queue this server creates. */
	public DeliveryConfig getDeliveryConfig() {
		return queue != null && !ownsQueue ? queue.getConfig() : deliveryConfig;
	}

	/**
	 * The queue (opened when the server starts, unless one was set), from this server's
	 * {@link #QUEUE} setting and the queue's own settings.
	 *
	 * @throws java.io.UncheckedIOException if the queue has no settings, or they are wrong
	 */
	public synchronized MailQueue getQueue() {
		if (queue == null) {
			try {
				FileSource root = getMaildropRoot();
				FileSource dir = queueDirectory(root);
				java.util.Properties settings = MailQueue.readSettings(dir);
				useQueueSettings(settings, dir);
				deliveryConfig.setMaildropRoot(root);
				deliveryConfig.setAccessControl(getAccessControl());
				QueueHistory history = QueueHistory.fromSettings(root, settings);
				MailQueue made = new MailQueue(dir, deliveryConfig);
				made.setReloader(() -> reloadQueueSettings(dir));
				if (history != null) {
					made.addQueueListener(history);
					queueHistory = history;
				}
				queue = made;
			} catch (IOException e) {
				throw new java.io.UncheckedIOException(e);
			}
			ownsQueue = true;
		}
		return queue;
	}

	/**
	 * The history of the queue this server made ({@link QueueHistory#HISTORY_PROP}), or null (none,
	 * or the queue is another server's)
	 */
	public synchronized QueueHistory getQueueHistory() {
		return ownsQueue ? queueHistory : null;
	}

	/** Share another server's queue (e.g. a submission server with the relay server). */
	public synchronized void setQueue(MailQueue queue) {
		this.queue = queue;
		this.ownsQueue = false;
	}

	/**
	 * Send a message from code: it is queued for delivery to {@code to} with the
	 * reverse-path {@code from} (null for {@code <>}).
	 *
	 * @return the queue id
	 */
	public String send(MailAddress from, List<MailAddress> to, Message message) throws IOException {
		FileSource dir = message.getWorkDirectory();
		FileSource tmp = dir.getFileSourceFactory().createTempFile("smtp", ".eml", dir);
		try {
			try (java.io.OutputStream out = new java.io.BufferedOutputStream(tmp.getOutputStream(), 64 * 1024)) {
				message.writeTo(out);
			}
			try (InputStream in = tmp.getInputStream()) {
				QueueEntry e = getQueue().enqueue(from, to, in, message.needsSmtpUtf8());
				return e.getId();
			}
		} finally {
			tmp.delete();
		}
	}

	/** True if the client address may relay without logging in. */
	public boolean isRelayAllowed(InetAddress client) {
		return relayNetworks.matches(client);
	}

	// ------------------------------------------------------------------ settings

	public String getHostname() {
		return hostname;
	}

	/** The name this server gives in its greeting and Received headers (the queue has its own) */
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	/**
	 * DKIM settings (shared by the servers that share a queue): add signing
	 * keys with {@code getDkim().addSigner(...)}.
	 */
	public Dkim getDkim() {
		return getDeliveryConfig().getDkim();
	}

	/** ARC settings (shared by the servers that share a queue). */
	public Arc getArc() {
		return getDeliveryConfig().getArc();
	}

	/** DMARC settings (shared by the servers that share a queue). */
	public Dmarc getDmarc() {
		return getDeliveryConfig().getDmarc();
	}

	/** The checks of a client before any mail: block lists, reverse DNS, HELO, pregreet, rates (this port's own). */
	/** The spam provider settings and check of this server. */
	public us.bringardner.parley.smtp.spam.Spam getSpam() {
		return spam;
	}

	public ConnectionChecks getConnectionChecks() {
		return connectionChecks;
	}

	/** SPF settings (shared by the servers that share a queue). */
	public Spf getSpf() {
		return getDeliveryConfig().getSpf();
	}

	/** Add a domain whose mail is delivered locally. */
	public void addLocalDomain(String domain) {
		getDeliveryConfig().addLocalDomain(domain);
	}

	public boolean isLocalDomain(String asciiDomain) {
		return getDeliveryConfig().isLocalDomain(asciiDomain);
	}

	public boolean isSubmission() {
		return submission;
	}

	/**
	 * Make this a submission server (RFC 6409: AUTH is required, and Date and Message-ID are added
	 * if missing), or not. A server made a submission server with this reads its settings again,
	 * with the {@value #SUBMISSION_PREFIX} prefix ({@value #SUBMISSIONS_PREFIX} with implicit TLS)
	 * instead of {@value #SMTP_PREFIX}; making it one when it is made
	 * ({@link #SmtpServer(int, String, boolean, boolean)}) is simpler.
	 *
	 * @throws IllegalArgumentException when a submission server with implicit TLS is made a relay:
	 *                                  there is no relay with implicit TLS
	 */
	public void setSubmission(boolean submission) {
		String prefix = getPropertyPrefix();
		if (!submission && SUBMISSIONS_PREFIX.equals(prefix)) {
			throw new IllegalArgumentException(NO_IMPLICIT_TLS_RELAY);
		}
		this.submission = submission;
		String before = prefix;
		if (submission && SMTP_PREFIX.equals(prefix)) {
			setPropertyPrefix(SUBMISSION_PREFIX);
		} else if (!submission && SUBMISSION_PREFIX.equals(prefix)) {
			setPropertyPrefix(SMTP_PREFIX);
		}
		if (!getPropertyPrefix().equals(before)) {
			readServerSettings(); // the new prefix's own settings
		}
	}

	public long getMaxMessageSize() {
		return maxMessageSize;
	}

	public void setMaxMessageSize(long maxMessageSize) {
		this.maxMessageSize = maxMessageSize;
	}

	public int getMaxRecipients() {
		return maxRecipients;
	}

	public void setMaxRecipients(int maxRecipients) {
		this.maxRecipients = maxRecipients;
	}

	public int getTimeout() {
		return timeout;
	}

	/** Close sessions that send nothing for this long (RFC 5321 section 4.5.3.2.7: at least 5 minutes). */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/**
	 * Only submission needs a login: mail for local users arrives without one, so the
	 * loginTimeLimit applies only to a submission server.
	 */
	@Override
	protected boolean isLoginRequired() {
		return isSubmission();
	}


	public int getMaxHops() {
		return maxHops;
	}

	/** Reject messages with more Received headers than this (mail loops, RFC 5321 section 6.3). */
	public void setMaxHops(int maxHops) {
		this.maxHops = maxHops;
	}

	/**
	 * Networks (e.g. "127.0.0.1/32", "10.0.0.0/8", "::1/128") that may relay without AUTH. Several may be
	 * given at once, separated by commas or spaces. Only address literals are accepted, never host names.
	 *
	 * @throws IllegalArgumentException for an entry that is not an address or network (a host name,
	 *  or a prefix length that doesn't fit the address, such as /33 or /-1)
	 */
	public synchronized void addRelayNetwork(String cidr) {
		relayNetworks = relayNetworks.and(AddressMatcher.parse(cidr));
	}

}
