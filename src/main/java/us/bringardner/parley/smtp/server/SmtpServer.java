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
 * One SmtpServer listens on one port. For port 25 (relay) plus 587 (submission,
 * RFC 6409) run two servers sharing one queue ({@link #setQueue(MailQueue)}),
 * as {@link #main(String[])} does.
 */
public class SmtpServer extends AbstractMailServer implements SMTP {

	private static final long serialVersionUID = 1L;

	public static final String SMTP_NAME = "JSmtp";
	public static final String CONFIG_PROP = SMTP_NAME + ".properties";
	public static final String ROOT_PROP = SMTP_NAME + ".root";
	public static final String FILE_SOURCE_PROP = SMTP_NAME + ".fileSource";
	public static final String QUEUE_DIRECTORY = ".smtp-queue";
	/** Where DMARC aggregate report data waits to be sent, under the maildrop root. */
	public static final String DMARC_REPORT_DIRECTORY = ".dmarc-reports";
	public static final long DEFAULT_MAX_MESSAGE_SIZE = 50L * 1024 * 1024;

	private static final String P = SMTP_NAME + ".";

	private volatile String hostname;
	private volatile boolean submission = Boolean.getBoolean(P + "submission");
	private volatile long maxMessageSize = Long.getLong(P + "maxMessageSize", DEFAULT_MAX_MESSAGE_SIZE);
	private volatile int maxRecipients = Integer.getInteger(P + "maxRecipients", 100);
	private volatile int timeout = Integer.getInteger(P + "timeout", 5 * 60 * 1000);
	private volatile int maxHops = Integer.getInteger(P + "maxHops", 100);
	//  Replaced (not changed) when a network is added, so isRelayAllowed needs no lock
	private volatile AddressMatcher relayNetworks = AddressMatcher.NONE;

	private final DeliveryConfig deliveryConfig = new DeliveryConfig();
	private MailQueue queue;
	private boolean ownsQueue;
	private boolean queueStarted;

	public SmtpServer(int port, String name, boolean secure) {
		super(port, name, "SmtpServer", secure);
		initMe();
		finishInit();
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
		SmtpServer s = new SmtpServer(implicitTls ? SUBMISSIONS_PORT : SUBMISSION_PORT, SMTP_NAME, implicitTls);
		s.setSubmission(true);
		return s;
	}

	/**
	 * Starts the relay server (JSmtp.port, default 25) and, if JSmtp.submissionPort
	 * (default 587; 0 for none) and JSmtp.submissionsPort (implicit TLS, default 0)
	 * are set, submission servers sharing its queue.
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.configure("SmtpServer", args, CONFIG_PROP);
		boolean secure = Boolean.parseBoolean(System.getProperty(P + "secure", "false"));
		int port = Integer.getInteger(P + "port", SMTP_PORT);
		SmtpServer relay = new SmtpServer(port, SMTP_NAME, secure);
		relay.start();
		System.out.println("SmtpServer started on port " + port);
		int sub = Integer.getInteger(P + "submissionPort", SUBMISSION_PORT);
		if (sub > 0) {
			SmtpServer s = new SmtpServer(sub, SMTP_NAME, false);
			s.setSubmission(true);
			s.setQueue(relay.getQueue());
			s.start();
			System.out.println("Submission server started on port " + sub);
		}
		int subs = Integer.getInteger(P + "submissionsPort", 0);
		if (subs > 0) {
			SmtpServer s = new SmtpServer(subs, SMTP_NAME, true);
			s.setSubmission(true);
			s.setQueue(relay.getQueue());
			s.start();
			System.out.println("Submission server (implicit TLS) started on port " + subs);
		}
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

		setRequireTls(Boolean.getBoolean(P + "requireTls"));
		initMaildropRoot(FILE_SOURCE_PROP, "JPop3.fileSource", ROOT_PROP, "JPop3.root", "/pop3", "C:/pop3");

		hostname = System.getProperty(P + "hostname");
		if (hostname == null) {
			try {
				hostname = InetAddress.getLocalHost().getCanonicalHostName();
			} catch (IOException | RuntimeException e) {
				hostname = "localhost";
			}
		}
		DeliveryConfig c = deliveryConfig;
		c.setHostname(hostname);
		String domains = System.getProperty(P + "domains", hostname);
		for (String d : domains.split(",")) {
			if (!d.trim().isEmpty()) {
				c.addLocalDomain(d.trim());
			}
		}
		String networks = System.getProperty(P + "relayNetworks");
		if (networks != null) {
			relayNetworks = relayNetworks.and(AddressMatcher.parse(networks));
		}
		c.setPostmaster(System.getProperty(P + "postmaster", "postmaster"));
		String aliases = System.getProperty(P + "aliases");
		if (aliases != null) {
			try (InputStream in = getFileSourceFactory().createFileSource(aliases).getInputStream()) {
				c.loadAliases(new String(in.readAllBytes(), StandardCharsets.UTF_8));
			} catch (IOException e) {
				logError("Can't read the aliases file " + aliases, e);
			}
		}
		String tmp = System.getProperty(P + "relayHost");
		if (tmp != null && !tmp.isEmpty()) {
			int colon = tmp.lastIndexOf(':');
			if (colon > 0) {
				c.setRelayHost(tmp.substring(0, colon));
				c.setRelayPort(Integer.parseInt(tmp.substring(colon + 1)));
			} else {
				c.setRelayHost(tmp);
			}
		}
		c.setRelayUser(System.getProperty(P + "relayUser"));
		c.setRelayPassword(System.getProperty(P + "relayPassword"));
		tmp = System.getProperty(P + "relayAuth");
		if (tmp != null && !tmp.trim().isEmpty()) {
			c.setRelayAuthMechanisms(java.util.Arrays.asList(tmp.trim().split("\\s*,\\s*")));
		}
		tmp = System.getProperty(P + "relayTls");
		if (tmp != null) {
			c.setRelayTlsMode(DeliveryConfig.TlsMode.valueOf(tmp.toUpperCase(Locale.ROOT)));
		}
		tmp = System.getProperty(P + "tls");
		if (tmp != null) {
			c.setTlsMode(DeliveryConfig.TlsMode.valueOf(tmp.toUpperCase(Locale.ROOT)));
		}
		c.setRemotePort(Integer.getInteger(P + "remotePort", SMTP_PORT));
		tmp = System.getProperty(P + "resolver", "jdk").trim().toLowerCase(Locale.ROOT);
		try {
			switch (tmp) {
			case "parley-dns":
			case "bjldns": { // older name, still accepted
				String list = System.getProperty(P + "dnsServers");
				ParleyDnsMxResolver r = new ParleyDnsMxResolver(list == null || list.isBlank() ? ParleyDnsMxResolver.systemServers()
						: ParleyDnsMxResolver.parseServers(list));
				r.setPreferIpv6(Boolean.getBoolean(P + "preferIpv6"));
				c.setResolver(r);
				break;
			}
			case "parley-dns-iterative":
			case "bjldns-iterative": // older name, still accepted
				c.setResolver(ParleyDnsMxResolver.iterative());
				break;
			case "jdk":
				break;
			default:
				logInfo("Unknown " + P + "resolver '" + tmp + "'; using the JDK resolver");
			}
		} catch (IOException | RuntimeException e) {
			logError("Can't set up the " + tmp + " resolver; using the JDK resolver", e);
		}
		Dkim dkim = c.getDkim();
		if (c.getResolver() instanceof ParleyDnsMxResolver) {
			dkim.setLookup(((ParleyDnsMxResolver) c.getResolver())::txt); // the same DNS servers as for MX lookups
		}
		dkim.setVerify(Boolean.parseBoolean(System.getProperty(P + "dkim.verify", "true")));
		tmp = System.getProperty(P + "dkim.keys");
		if (tmp != null && !tmp.isBlank()) {
			try {
				dkim.addSigners(tmp, System.getProperty(P + "dkim.headers"));
			} catch (IOException | GeneralSecurityException | RuntimeException e) {
				logError("Can't load the DKIM keys (" + P + "dkim.keys); mail is sent unsigned", e);
			}
		}
		Spf spf = c.getSpf();
		if (c.getResolver() instanceof ParleyDnsMxResolver) {
			spf.setDns(((ParleyDnsMxResolver) c.getResolver())::records);
		}
		spf.setCheck(Boolean.parseBoolean(System.getProperty(P + "spf.check", "true")));
		spf.setRejectFail(Boolean.getBoolean(P + "spf.rejectFail"));
		Dmarc dmarc = c.getDmarc();
		if (c.getResolver() instanceof ParleyDnsMxResolver) {
			dmarc.setDns(((ParleyDnsMxResolver) c.getResolver())::txt);
		}
		dmarc.setCheck(Boolean.parseBoolean(System.getProperty(P + "dmarc.check", "true")));
		dmarc.setEnforce(Boolean.getBoolean(P + "dmarc.enforce"));
		DmarcReporter reporter = dmarc.getReporter();
		reporter.setAggregate(Boolean.getBoolean(P + "dmarc.aggregateReports"));
		reporter.setFailure(Boolean.getBoolean(P + "dmarc.failureReports"));
		reporter.setHostname(hostname);
		reporter.setOrgName(System.getProperty(P + "dmarc.reportOrgName", hostname));
		reporter.setEmail(System.getProperty(P + "dmarc.reportEmail", "postmaster@" + hostname));
		tmp = System.getProperty(P + "dmarc.reportIntervalHours");
		if (tmp != null) {
			reporter.setIntervalMillis((long) (Double.parseDouble(tmp) * 3_600_000));
		}
		reporter.setMaxFailurePerHour(Integer.getInteger(P + "dmarc.maxFailureReportsPerHour", 10));
		tmp = System.getProperty(P + "dmarc.publicSuffixList");
		if (tmp != null && !tmp.isBlank()) {
			try {
				dmarc.setPublicSuffixList(PublicSuffixList.load(new File(tmp)));
			} catch (IOException e) {
				logError("Can't read the public suffix list " + tmp + "; using the included copy", e);
			}
		}
		Arc arc = c.getArc();
		arc.setVerify(Boolean.parseBoolean(System.getProperty(P + "arc.verify", "true")));
		arc.setSeal(Boolean.parseBoolean(System.getProperty(P + "arc.seal", "true")));
		arc.setDomain(System.getProperty(P + "arc.domain"));
		tmp = System.getProperty(P + "arc.trustedSealers");
		if (tmp != null) {
			arc.addTrustedSealers(tmp);
		}
		c.setWorkers(Integer.getInteger(P + "queue.workers", 4));
		tmp = System.getProperty(P + "queue.retry");
		if (tmp != null) {
			String[] p = tmp.split(",");
			long[] schedule = new long[p.length];
			for (int i = 0; i < p.length; i++) {
				schedule[i] = (long) (Double.parseDouble(p[i].trim()) * 60_000);
			}
			c.setRetrySchedule(schedule);
		}
		tmp = System.getProperty(P + "queue.maxAgeHours");
		if (tmp != null) {
			c.setMaxAge((long) (Double.parseDouble(tmp) * 3_600_000));
		}
		tmp = System.getProperty(P + "queue.delayWarningHours");
		if (tmp != null) {
			c.setDelayWarning((long) (Double.parseDouble(tmp) * 3_600_000));
		}

		IAccessControlList acl = getAccessControl();
		if (acl == null) {
			logInfo("No access control is configured for " + getName() + "; no one can log in and no local users exist");
		}
	}

	// ------------------------------------------------------------------ life cycle

	@Override
	public synchronized void start() {
		try {
			startQueue();
		} catch (IOException e) {
			logError("Can't start the mail queue", e);
			throw new java.io.UncheckedIOException(e);
		}
		super.start();
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

	@Override
	public void stop() {
		super.stop();
		synchronized (this) {
			if (queueStarted) {
				getDeliveryConfig().getDmarc().getReporter().stop();
				queue.stop();
				queueStarted = false;
			}
		}
	}

	// ------------------------------------------------------------------ mail

	/** Routing, local domains, aliases and retry settings of the queue this server creates. */
	public DeliveryConfig getDeliveryConfig() {
		return queue != null && !ownsQueue ? queue.getConfig() : deliveryConfig;
	}

	/** The queue (created when the server starts, unless one was set). */
	public synchronized MailQueue getQueue() {
		if (queue == null) {
			try {
				deliveryConfig.setMaildropRoot(getMaildropRoot());
				deliveryConfig.setAccessControl(getAccessControl());
				queue = new MailQueue(getMaildropRoot().getChild(QUEUE_DIRECTORY), deliveryConfig);
			} catch (IOException e) {
				throw new java.io.UncheckedIOException(e);
			}
			ownsQueue = true;
		}
		return queue;
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

	public void setHostname(String hostname) {
		this.hostname = hostname;
		deliveryConfig.setHostname(hostname);
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

	/** Submission mode (RFC 6409): AUTH is required, and Date and Message-ID are added if missing. */
	public void setSubmission(boolean submission) {
		this.submission = submission;
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
	 * The shared LoginFailureDelay setting (see AbstractCoreServer) defaults to the older
	 * JSmtp.loginFailureDelay system property, else 1000 ms.
	 */
	/**
	 * Only submission needs a login: mail for local users arrives without one, so the
	 * LoginTimeLimit applies only to a submission server.
	 */
	@Override
	protected boolean isLoginRequired() {
		return isSubmission();
	}

	@Override
	protected int getDefaultLoginFailureDelay() {
		return Integer.getInteger(P + "loginFailureDelay", DEFAULT_LOGIN_FAILURE_DELAY);
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
