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
import us.bringardner.parley.smtp.dkim.Arc;
import us.bringardner.parley.smtp.dmarc.Dmarc;
import us.bringardner.parley.smtp.dmarc.DmarcReporter;
import us.bringardner.parley.smtp.dmarc.PublicSuffixList;
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
 * its own settings, under its prefix ({@value #SMTP_PREFIX}, {@value #SMTPS_PREFIX},
 * {@value #SUBMISSION_PREFIX} or {@value #SUBMISSIONS_PREFIX}), from its configuration (the system
 * properties for a server made by code). Whether it is a relay or a submission server comes from how
 * it is made ({@link #SmtpServer(int, String, boolean, boolean)}, {@link #submissionServer(boolean)}).
 * <p>
 * Its own settings are about its port: {@code hostname} (required: the greeting and Received
 * headers), {@code requireTls}, {@code relayNetworks}, {@code maxMessageSize}, {@code maxRecipients},
 * {@code timeout}, {@code maxHops}, the checks of incoming mail ({@code dkim.verify},
 * {@code spf.check}, {@code spf.rejectFail}, {@code dmarc.check}, {@code dmarc.enforce},
 * {@code dmarc.publicSuffixList}, {@code arc.verify}) and where its queue is ({@value #QUEUE},
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
	/** The prefix of the properties of an SMTP relay server with implicit TLS. */
	public static final String SMTPS_PREFIX = "parley.mail.smtps";
	/** The prefix of the properties of a submission server (RFC 6409, port 587). */
	public static final String SUBMISSION_PREFIX = "parley.mail.submission";
	/** The prefix of the properties of a submission server with implicit TLS (RFC 8314, port 465). */
	public static final String SUBMISSIONS_PREFIX = "parley.mail.submissions";
	/** A settings file for the servers' configuration (see parley-net's ServerLauncher). */
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

	public SmtpServer(int port, String name, boolean secure) {
		this(port, name, secure, false);
	}

	/**
	 * @param secure     implicit TLS
	 * @param submission a submission server (RFC 6409: AUTH required), reading its settings with
	 *                   {@value #SUBMISSION_PREFIX} ({@value #SUBMISSIONS_PREFIX} with implicit TLS)
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
		return secure ? SMTPS_PREFIX : SMTP_PREFIX;
	}

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
	 * Run the relay (parley.mail.smtp.port, default 25; 0 turns it off), submission
	 * (parley.mail.submission.port, default 587; 0 turns it off) and, when
	 * parley.mail.submissions.port is set, submission with implicit TLS, until the process is stopped;
	 * see {@link SmtpProviders} and parley-net's ServerMain.launch. Each server reads its own settings
	 * with its prefix: parley.mail.smtp, parley.mail.submission and parley.mail.submissions.
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.launch("SmtpServer", args, "smtp", "submission", "submissions");
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
		timeout = setting("timeout", 5 * 60 * 1000);
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
		DeliveryConfig c = deliveryConfig;
		String host = queueSetting(q, "hostname");
		if (host == null) {
			throw new IOException("The mail queue's hostname isn't set" + where);
		}
		c.setHostname(host);
		String domains = queueSetting(q, "domains");
		if (domains == null && c.getLocalDomains().isEmpty()) {
			throw new IOException("The mail queue's domains aren't set" + where);
		}
		if (domains != null) {
			for (String d : domains.split(",")) {
				if (!d.trim().isEmpty()) {
					c.addLocalDomain(d.trim());
				}
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
		tmp = queueSetting(q, "relayHost");
		if (tmp != null) {
			int colon = tmp.lastIndexOf(':');
			if (colon > 0) {
				c.setRelayHost(tmp.substring(0, colon));
				c.setRelayPort(Integer.parseInt(tmp.substring(colon + 1)));
			} else {
				c.setRelayHost(tmp);
			}
		}
		c.setRelayUser(queueSetting(q, "relayUser"));
		tmp = queueSetting(q, "relayPassword");
		if (tmp != null) {
			// a secret: the settings name where it is kept (@keychain:..., @file:..., @env:...), never the password
			if (!us.bringardner.parley.files.credentials.CredentialRef.isReference(tmp)) {
				throw new IOException("The mail queue's relayPassword must name where the password is kept (@keychain:..., @file:..., @env:...), not hold it"
						+ where);
			}
			char[] secret = us.bringardner.parley.files.credentials.Credentials.secret(tmp,
					us.bringardner.parley.files.credentials.CredentialRequest.forProperty("relayPassword"));
			c.setRelayPassword(new String(secret));
			java.util.Arrays.fill(secret, '\0');
		}
		tmp = queueSetting(q, "relayAuth");
		if (tmp != null) {
			c.setRelayAuthMechanisms(java.util.Arrays.asList(tmp.split("\\s*,\\s*")));
		}
		tmp = queueSetting(q, "relayTls");
		if (tmp != null) {
			c.setRelayTlsMode(DeliveryConfig.TlsMode.valueOf(tmp.toUpperCase(Locale.ROOT)));
		}
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
		// no default from another setting: reports say who sends them only when told
		boolean noOrg = reporter.getOrgName() == null || reporter.getOrgName().isEmpty() || "localhost".equals(reporter.getOrgName());
		boolean noEmail = reporter.getEmail() == null || reporter.getEmail().endsWith("@localhost");
		if ((reporter.isAggregate() || reporter.isFailure()) && (noOrg || noEmail)) {
			throw new IOException("DMARC reports need dmarc.reportOrgName and dmarc.reportEmail" + where);
		}
		tmp = queueSetting(q, "dmarc.reportIntervalHours");
		if (tmp != null) {
			reporter.setIntervalMillis((long) (Double.parseDouble(tmp) * 3_600_000));
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
			String[] p = tmp.split(",");
			long[] schedule = new long[p.length];
			for (int i = 0; i < p.length; i++) {
				schedule[i] = (long) (Double.parseDouble(p[i].trim()) * 60_000);
			}
			c.setRetrySchedule(schedule);
		}
		tmp = queueSetting(q, "maxAgeHours");
		if (tmp != null) {
			c.setMaxAge((long) (Double.parseDouble(tmp) * 3_600_000));
		}
		tmp = queueSetting(q, "delayWarningHours");
		if (tmp != null) {
			c.setDelayWarning((long) (Double.parseDouble(tmp) * 3_600_000));
		}
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
		getQueue().start();
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
				queue = new MailQueue(dir, deliveryConfig);
				QueueHistory history = QueueHistory.fromSettings(root, settings);
				if (history != null) {
					queue.addQueueListener(history);
					queueHistory = history;
				}
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
	 */
	public void setSubmission(boolean submission) {
		this.submission = submission;
		String prefix = getPropertyPrefix();
		String before = prefix;
		if (submission && SMTP_PREFIX.equals(prefix)) {
			setPropertyPrefix(SUBMISSION_PREFIX);
		} else if (submission && SMTPS_PREFIX.equals(prefix)) {
			setPropertyPrefix(SUBMISSIONS_PREFIX);
		} else if (!submission && SUBMISSION_PREFIX.equals(prefix)) {
			setPropertyPrefix(SMTP_PREFIX);
		} else if (!submission && SUBMISSIONS_PREFIX.equals(prefix)) {
			setPropertyPrefix(SMTPS_PREFIX);
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
