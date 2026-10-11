package us.bringardner.parley.smtp.queue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.smtp.dkim.Arc;
import us.bringardner.parley.smtp.dkim.Dkim;
import us.bringardner.parley.smtp.dmarc.Dmarc;
import us.bringardner.parley.smtp.spf.Spf;

/** How the queue delivers mail: local domains and users, routing, retries. */
public class DeliveryConfig {

	private final Dkim dkim = new Dkim();
	private final Spf spf = new Spf();
	private final Dmarc dmarc = new Dmarc();
	private final Arc arc = new Arc();

	/** TLS for outgoing connections. */
	public enum TlsMode {
		/** Never use STARTTLS. */
		NONE,
		/** Use STARTTLS when offered, without checking the certificate (RFC 7435). */
		OPPORTUNISTIC,
		/** Require STARTTLS and a valid certificate (for a smart host). */
		REQUIRED
	}

	private String hostname = "localhost";
	private final Set<String> localDomains = new LinkedHashSet<>();
	private FileSource maildropRoot;
	private IAccessControlList accessControl;
	private final Map<String, List<String>> aliases = new HashMap<>();
	private String postmaster = "postmaster";
	private boolean createDefaultMailboxes = true;

	private MxResolver resolver = new DnsMxResolver();
	private int remotePort = 25;
	private String relayHost;
	private int relayPort = 587;
	private String relayUser;
	private String relayPassword;
	private List<String> relayAuthMechanisms = new ArrayList<>();
	private TlsMode tlsMode = TlsMode.OPPORTUNISTIC;
	private TlsMode relayTlsMode = TlsMode.REQUIRED;

	/** Minutes between attempts; the last value repeats. */
	private long[] retrySchedule = {60_000, 5 * 60_000, 15 * 60_000, 30 * 60_000, 60 * 60_000, 2 * 60 * 60_000};
	private long maxAge = 5L * 24 * 60 * 60_000;
	private long delayWarning = 4L * 60 * 60_000;
	private int connectTimeout = 30_000;
	private int readTimeout = 5 * 60_000;
	private int workers = 4;
	/** Messages larger than this are returned with headers only. */
	private long maxReturnSize = 1024 * 1024;

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	/** Domains (lower case, A-labels) whose mail is delivered here. */
	public Set<String> getLocalDomains() {
		return localDomains;
	}

	public void addLocalDomain(String domain) {
		localDomains.add(java.net.IDN.toASCII(domain.trim(), java.net.IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT));
	}

	public boolean isLocalDomain(String asciiDomain) {
		return localDomains.contains(asciiDomain.toLowerCase(Locale.ROOT));
	}

	public FileSource getMaildropRoot() {
		return maildropRoot;
	}

	public void setMaildropRoot(FileSource maildropRoot) {
		this.maildropRoot = maildropRoot;
	}

	public IAccessControlList getAccessControl() {
		return accessControl;
	}

	public void setAccessControl(IAccessControlList accessControl) {
		this.accessControl = accessControl;
	}

	/** Aliases by lower-case local part: local user names or full addresses. */
	public Map<String, List<String>> getAliases() {
		return aliases;
	}

	public void addAlias(String alias, String... targets) {
		List<String> list = aliases.computeIfAbsent(alias.toLowerCase(Locale.ROOT), k -> new ArrayList<>());
		for (String t : targets) {
			list.add(t.trim());
		}
	}

	/**
	 * Read an aliases file: lines like {@code sales: tony, jose@example.com};
	 * "#" starts a comment.
	 */
	public void loadAliases(String text) {
		for (String line : text.split("\r?\n")) {
			int hash = line.indexOf('#');
			if (hash >= 0) {
				line = line.substring(0, hash);
			}
			int colon = line.indexOf(':');
			if (colon <= 0) {
				continue;
			}
			String[] targets = line.substring(colon + 1).split(",");
			List<String> list = new ArrayList<>();
			for (String t : targets) {
				if (!t.trim().isEmpty()) {
					list.add(t.trim());
				}
			}
			if (!list.isEmpty()) {
				addAlias(line.substring(0, colon).trim(), list.toArray(new String[0]));
			}
		}
	}

	/** The user that receives postmaster mail (RFC 5321 section 4.5.1). */
	public String getPostmaster() {
		return postmaster;
	}

	public void setPostmaster(String postmaster) {
		this.postmaster = postmaster;
	}

	public boolean isCreateDefaultMailboxes() {
		return createDefaultMailboxes;
	}

	public void setCreateDefaultMailboxes(boolean createDefaultMailboxes) {
		this.createDefaultMailboxes = createDefaultMailboxes;
	}

	public MxResolver getResolver() {
		return resolver;
	}

	public void setResolver(MxResolver resolver) {
		this.resolver = resolver;
	}

	public int getRemotePort() {
		return remotePort;
	}

	public void setRemotePort(int remotePort) {
		this.remotePort = remotePort;
	}

	/** A smart host that receives all non-local mail, or null to deliver directly (MX). */
	public String getRelayHost() {
		return relayHost;
	}

	public void setRelayHost(String relayHost) {
		this.relayHost = relayHost;
	}

	public int getRelayPort() {
		return relayPort;
	}

	public void setRelayPort(int relayPort) {
		this.relayPort = relayPort;
	}

	public String getRelayUser() {
		return relayUser;
	}

	public void setRelayUser(String relayUser) {
		this.relayUser = relayUser;
	}

	public String getRelayPassword() {
		return relayPassword;
	}

	/**
	 * SASL mechanisms to log in to the smart host with, best first (SCRAM-SHA-256, SCRAM-SHA-1,
	 * CRAM-MD5, PLAIN, LOGIN). The first one the smart host offers is used. Empty (the default)
	 * means AUTH PLAIN. With SCRAM the password is never sent, and the smart host has to prove
	 * it knows it.
	 */
	public List<String> getRelayAuthMechanisms() {
		return relayAuthMechanisms;
	}

	public void setRelayAuthMechanisms(List<String> relayAuthMechanisms) {
		this.relayAuthMechanisms = relayAuthMechanisms == null ? new ArrayList<>()
				: new ArrayList<>(relayAuthMechanisms);
	}

	public void setRelayPassword(String relayPassword) {
		this.relayPassword = relayPassword;
	}

	public TlsMode getTlsMode() {
		return tlsMode;
	}

	public void setTlsMode(TlsMode tlsMode) {
		this.tlsMode = tlsMode;
	}

	public TlsMode getRelayTlsMode() {
		return relayTlsMode;
	}

	public void setRelayTlsMode(TlsMode relayTlsMode) {
		this.relayTlsMode = relayTlsMode;
	}

	public long[] getRetrySchedule() {
		return retrySchedule;
	}

	public void setRetrySchedule(long... retrySchedule) {
		if (retrySchedule.length == 0) {
			throw new IllegalArgumentException("Empty retry schedule");
		}
		this.retrySchedule = retrySchedule;
	}

	/** The wait before attempt {@code n + 1} after {@code n} failed attempts. */
	public long retryDelay(int attempts) {
		return retrySchedule[Math.min(Math.max(0, attempts - 1), retrySchedule.length - 1)];
	}

	public long getMaxAge() {
		return maxAge;
	}

	/** Give up (and return the message) after this long. */
	public void setMaxAge(long maxAge) {
		this.maxAge = maxAge;
	}

	public long getDelayWarning() {
		return delayWarning;
	}

	/** Tell the sender a message is delayed after this long. */
	public void setDelayWarning(long delayWarning) {
		this.delayWarning = delayWarning;
	}

	public int getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public int getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
	}

	public int getWorkers() {
		return workers;
	}

	public void setWorkers(int workers) {
		this.workers = Math.max(1, workers);
	}

	public long getMaxReturnSize() {
		return maxReturnSize;
	}

	public void setMaxReturnSize(long maxReturnSize) {
		this.maxReturnSize = maxReturnSize;
	}

	/** DKIM signing keys and verification settings (RFC 6376). */
	public Dkim getDkim() {
		return dkim;
	}

	/** ARC settings (RFC 8617). */
	public Arc getArc() {
		return arc;
	}

	/** DMARC settings (RFC 7489). */
	public Dmarc getDmarc() {
		return dmarc;
	}

	/** SPF checking settings (RFC 7208). */
	public Spf getSpf() {
		return spf;
	}
}
