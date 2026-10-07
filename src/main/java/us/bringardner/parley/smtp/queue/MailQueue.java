package us.bringardner.parley.smtp.queue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.SmtpStreams;
import us.bringardner.parley.smtp.dkim.Arc;
import us.bringardner.parley.smtp.dkim.ArcSealer;
import us.bringardner.parley.smtp.dkim.Dkim;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.core.NamedThreadFactory;

/**
 * The persistent mail queue of the SMTP server. A message accepted by the server
 * (or submitted by code) is written to the queue directory before the server
 * replies 250, so it survives a restart (RFC 5321 section 6.1). Workers then
 * deliver it: into local users' INBOXes, or to the MX hosts of other domains,
 * retrying temporary failures on a schedule, and returning delivery status
 * notifications (RFC 3464) to the sender when asked or when delivery fails.
 */
public class MailQueue {

	private static final System.Logger LOG = System.getLogger(MailQueue.class.getName());
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final AtomicLong SEQUENCE = new AtomicLong();
	/** Alias expansion deeper than this is a loop. */
	private static final int MAX_ALIAS_DEPTH = 10;

	private final FileSource dir;
	private final DeliveryConfig config;
	private final LocalDelivery local;
	private final RemoteDelivery remote;
	private final Map<String, QueueEntry> entries = new ConcurrentHashMap<>();
	private final Set<String> active = ConcurrentHashMap.newKeySet();
	private final Object lock = new Object();
	private volatile boolean running;
	private Thread scheduler;
	private ExecutorService workers;
	private int users;

	public MailQueue(FileSource dir, DeliveryConfig config) {
		this.dir = dir;
		this.config = config;
		this.local = new LocalDelivery(config);
		this.remote = new RemoteDelivery(config);
	}

	public FileSource getDirectory() {
		return dir;
	}

	public DeliveryConfig getConfig() {
		return config;
	}

	public LocalDelivery getLocalDelivery() {
		return local;
	}

	// ------------------------------------------------------------------ life cycle

	/** Load the queue and start delivering. Every start() must be matched by stop(). */
	public synchronized void start() throws IOException {
		if (users++ > 0) {
			return;
		}
		if (!dir.exists() && !dir.mkdirs()) {
			throw new IOException("Can't create the queue directory " + dir.getAbsolutePath());
		}
		FileSource[] list = dir.listFiles();
		if (list != null) {
			for (FileSource f : list) {
				String name = f.getName();
				if (name.startsWith(".")) {
					f.delete(); // an incomplete message or index from before a crash
				} else if (name.endsWith(".env")) {
					try {
						QueueEntry e = QueueEntry.read(f);
						if (content(e.id).exists()) {
							entries.put(e.id, e);
						} else {
							f.delete();
						}
					} catch (IOException e) {
						LOG.log(Level.WARNING, "Skipping damaged queue file " + name, e);
					}
				}
			}
		}
		running = true;
		workers = Executors.newFixedThreadPool(config.getWorkers(), new NamedThreadFactory("SmtpQueueWorker"));
		scheduler = new Thread(this::schedule, "SmtpQueue");
		scheduler.setDaemon(true);
		scheduler.start();
	}

	public synchronized void stop() {
		if (users == 0 || --users > 0) {
			return;
		}
		running = false;
		wake();
		if (workers != null) {
			workers.shutdown();
			try {
				workers.awaitTermination(30, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	public boolean isRunning() {
		return running;
	}

	/** Look at the queue now (after a new message, or for tests). */
	public void wake() {
		synchronized (lock) {
			lock.notifyAll();
		}
	}

	/** Try every pending message now, ignoring the retry schedule. */
	public void flush() {
		for (QueueEntry e : entries.values()) {
			synchronized (e) {
				for (QueuedRecipient r : e.recipients) {
					r.nextAttempt = 0;
				}
			}
		}
		wake();
	}

	/** The messages in the queue. */
	public Collection<QueueEntry> getEntries() {
		return entries.values();
	}

	private void schedule() {
		while (running) {
			long now = System.currentTimeMillis();
			for (QueueEntry e : entries.values()) {
				if (e.nextAttempt() <= now && active.add(e.id)) {
					try {
						workers.submit(() -> {
							try {
								process(e);
							} catch (Throwable t) {
								LOG.log(Level.ERROR, "Error delivering " + e.id, t);
							} finally {
								active.remove(e.id);
							}
						});
					} catch (RuntimeException rejected) {
						active.remove(e.id);
					}
				}
			}
			synchronized (lock) {
				try {
					lock.wait(1000);
				} catch (InterruptedException ex) {
					return;
				}
			}
		}
	}

	// ------------------------------------------------------------------ adding messages

	/** A new queue id: time, sequence and randomness, in base 36. */
	public static String newId() {
		return Long.toString(System.currentTimeMillis(), 36).toUpperCase(Locale.ROOT)
				+ Long.toString(SEQUENCE.incrementAndGet() % 1_000_000L, 36).toUpperCase(Locale.ROOT)
				+ Integer.toString(RANDOM.nextInt(36 * 36 * 36), 36).toUpperCase(Locale.ROOT);
	}

	/** Where a message being received is written before {@link #commit}. */
	public FileSource incoming(String id) throws IOException {
		if (!dir.exists()) {
			dir.mkdirs();
		}
		return dir.getChild(".in-" + id + ".eml");
	}

	FileSource content(String id) throws IOException {
		return dir.getChild(id + ".eml");
	}

	private FileSource envelope(String id) throws IOException {
		return dir.getChild(id + ".env");
	}

	/**
	 * Put a received message in the queue: its content (written to
	 * {@link #incoming(String)}) becomes the queue file and the envelope is saved.
	 * After this returns, the message is safe.
	 */
	public void commit(QueueEntry e, FileSource incoming) throws IOException {
		FileSource target = content(e.id);
		if (!incoming.renameTo(target)) {
			throw new IOException("Can't move " + incoming.getAbsolutePath() + " into the queue");
		}
		try {
			e.write(envelope(e.id));
		} catch (IOException ex) {
			target.delete();
			throw ex;
		}
		entries.put(e.id, e);
		wake();
	}

	/**
	 * Sign a message that is being queued with the DKIM key of its From domain
	 * (see {@link Dkim#signerFor(String)}): the
	 * DKIM-Signature field is put at the top of the file. Nothing happens if
	 * no key fits. A failure is logged and the message stays unsigned.
	 *
	 * @param id       the queue id (for the temporary file)
	 * @param incoming the message, from {@link #incoming(String)}
	 * @return true if the message was signed
	 */
	public boolean dkimSign(String id, FileSource incoming) {
		Dkim dkim = config.getDkim();
		if (!dkim.isSigning()) {
			return false;
		}
		try {
			String domain = null;
			try (InputStream in = new BufferedInputStream(incoming.getInputStream(), 64 * 1024)) {
				HeaderFields.Field from = HeaderFields.read(in).get("From");
				if (from != null) {
					domain = HeaderFields.addressDomain(from.getValue());
				}
			}
			DkimSigner signer = dkim.signerFor(domain);
			if (signer == null) {
				return false;
			}
			String field;
			try (InputStream in = new BufferedInputStream(incoming.getInputStream(), 64 * 1024)) {
				field = signer.sign(in);
			}
			HeaderRewriter.prepend(incoming, incoming(id + "k"), field);
			return true;
		} catch (IOException | GeneralSecurityException | RuntimeException ex) {
			LOG.log(Level.WARNING, "Can't DKIM-sign " + id + "; it is sent unsigned", ex);
			return false;
		}
	}

	/**
	 * Add our ARC set (RFC 8617) to a received message before it is forwarded
	 * to another server (an alias with outside members, say), so the next
	 * receiver can see the results we found even though forwarding may break
	 * SPF and DKIM. The chain status comes from the arc= result in our
	 * Authentication-Results field. Done once per message; a failure is logged
	 * and the message goes unsealed.
	 */
	void arcSeal(QueueEntry e, FileSource content) {
		Arc arc = config.getArc();
		ArcSealer sealer = arc.sealer(config.getDkim(), config.getHostname());
		if (sealer == null) {
			return;
		}
		try {
			String set;
			try (InputStream in = new BufferedInputStream(content.getInputStream(), 64 * 1024)) {
				set = sealer.seal(in, config.getHostname());
			}
			synchronized (e) {
				if (set != null) {
					HeaderRewriter.prepend(content, incoming(e.id + "s"), set);
					e.size = content.length();
				}
				e.arcSealed = true;
				e.write(envelope(e.id));
			}
		} catch (IOException | GeneralSecurityException | RuntimeException ex) {
			LOG.log(Level.WARNING, "Can't ARC-seal " + e.id + "; it is forwarded unsealed", ex);
		}
	}

	/**
	 * Queue a message from code (e.g. for an application sending mail). The
	 * content is copied with CRLF line ends.
	 */
	public QueueEntry enqueue(MailAddress from, List<MailAddress> to, InputStream content, boolean smtpUtf8)
			throws IOException {
		QueueEntry e = new QueueEntry(newId());
		e.from = from;
		e.smtpUtf8 = smtpUtf8;
		for (MailAddress a : to) {
			e.recipients.add(new QueuedRecipient(a, null, null));
		}
		FileSource in = incoming(e.id);
		boolean eight = false;
		long size = 0;
		try (OutputStream out = new BufferedOutputStream(in.getOutputStream(), 64 * 1024);
				SmtpStreams.CrlfOutputStream crlf = new SmtpStreams.CrlfOutputStream(out);
				InputStream src = new BufferedInputStream(content, 64 * 1024)) {
			byte[] buf = new byte[64 * 1024];
			int n;
			while ((n = src.read(buf)) > 0) {
				for (int i = 0; i < n && !eight; i++) {
					eight = buf[i] < 0;
				}
				crlf.write(buf, 0, n);
				size += n;
			}
		}
		e.body = eight ? QueueEntry.Body.EIGHT_BIT : QueueEntry.Body.SEVEN_BIT;
		e.size = dkimSign(e.id, in) ? in.length() : size;
		commit(e, in);
		return e;
	}

	// ------------------------------------------------------------------ delivery

	/** One delivery pass over an entry's due recipients. */
	void process(QueueEntry e) throws IOException {
		FileSource content = content(e.id);
		long now = System.currentTimeMillis();
		List<QueuedRecipient> failed = new ArrayList<>();
		List<QueuedRecipient> succeeded = new ArrayList<>();
		List<String> successActions = new ArrayList<>();
		List<QueuedRecipient> delayed = new ArrayList<>();
		Map<String, List<QueuedRecipient>> remoteByDomain = new LinkedHashMap<>();

		synchronized (e) {
			// local recipients and alias expansion (the list can grow while we go)
			for (int i = 0; i < e.recipients.size(); i++) {
				QueuedRecipient r = e.recipients.get(i);
				if (r.status != QueuedRecipient.Status.PENDING || r.nextAttempt > now) {
					continue;
				}
				String domain = r.address.getAsciiDomain();
				if (config.isLocalDomain(domain)) {
					deliverLocal(e, content, r, succeeded, successActions);
				} else {
					String key = config.getRelayHost() != null ? "" : domain;
					remoteByDomain.computeIfAbsent(key, k -> new ArrayList<>()).add(r);
				}
			}
		}
		if (!remoteByDomain.isEmpty() && e.inbound && !e.arcSealed) {
			arcSeal(e, content);
		}
		for (Map.Entry<String, List<QueuedRecipient>> group : remoteByDomain.entrySet()) {
			Map<QueuedRecipient, RemoteDelivery.Result> results = remote.deliver(e, content, group.getValue(), group.getKey());
			synchronized (e) {
				for (Map.Entry<QueuedRecipient, RemoteDelivery.Result> res : results.entrySet()) {
					QueuedRecipient r = res.getKey();
					RemoteDelivery.Result result = res.getValue();
					r.remoteMta = result.remoteMta;
					if (result.error == null) {
						r.status = QueuedRecipient.Status.DELIVERED;
						r.lastStatus = "2.0.0";
						r.lastResult = "relayed to " + result.remoteMta;
						if (!result.dsnPassedOn && r.wants(QueuedRecipient.Notify.SUCCESS)) {
							succeeded.add(r);
							successActions.add("relayed");
						}
					} else {
						r.lastStatus = result.error.getStatus();
						r.lastResult = result.error.getDiagnostic() != null ? result.error.getDiagnostic() : result.error.getMessage();
						if (result.error.isPermanent()) {
							r.status = QueuedRecipient.Status.FAILED;
						} else {
							retryLater(e, r, now);
						}
					}
				}
			}
		}
		synchronized (e) {
			for (QueuedRecipient r : e.recipients) {
				if (r.attempts == 0 && r.status != QueuedRecipient.Status.PENDING) {
					r.attempts = 1;
				}
				if (r.status == QueuedRecipient.Status.FAILED && r.nextAttempt != Long.MIN_VALUE) {
					r.nextAttempt = Long.MIN_VALUE; // reported
					if (r.wants(QueuedRecipient.Notify.FAILURE)) {
						failed.add(r);
					}
				}
				if (r.status == QueuedRecipient.Status.PENDING && !r.delayNotified && now - e.created >= config.getDelayWarning()) {
					r.delayNotified = true;
					if (r.wants(QueuedRecipient.Notify.DELAY)) {
						delayed.add(r);
					}
				}
			}
			if (e.from != null) {
				notify(e, content, DsnBuilder.Kind.FAILURE, failed, null);
				notify(e, content, DsnBuilder.Kind.DELAY, delayed, null);
				notify(e, content, DsnBuilder.Kind.SUCCESS, succeeded, successActions);
			} else if (!failed.isEmpty()) {
				LOG.log(Level.WARNING, "A bounce couldn't be delivered and is discarded: " + e);
			}
			if (e.isPending()) {
				e.write(envelope(e.id));
			} else {
				entries.remove(e.id);
				envelope(e.id).delete();
				content.delete();
			}
		}
	}

	private void retryLater(QueueEntry e, QueuedRecipient r, long now) {
		r.attempts++;
		if (now - e.created >= config.getMaxAge()) {
			r.status = QueuedRecipient.Status.FAILED;
			r.lastResult = "Gave up after " + r.attempts + " attempts: " + r.lastResult;
			if (r.lastStatus == null || r.lastStatus.isEmpty() || r.lastStatus.startsWith("4")) {
				r.lastStatus = "4.4.7"; // delivery time expired
			}
		} else {
			r.nextAttempt = now + config.retryDelay(r.attempts);
		}
	}

	private void deliverLocal(QueueEntry e, FileSource content, QueuedRecipient r, List<QueuedRecipient> succeeded,
			List<String> actions) {
		long now = System.currentTimeMillis();
		LocalDelivery.Target target;
		try {
			target = local.find(r.address.getLocalPart());
		} catch (IOException ex) {
			r.lastStatus = "4.3.0";
			r.lastResult = "Local lookup failed: " + ex.getMessage();
			retryLater(e, r, now);
			return;
		}
		if (target == null) {
			r.status = QueuedRecipient.Status.FAILED;
			r.lastStatus = "5.1.1";
			r.lastResult = "User unknown: " + r.address;
			return;
		}
		if (target.members != null) {
			if (r.depth >= MAX_ALIAS_DEPTH) {
				r.status = QueuedRecipient.Status.FAILED;
				r.lastStatus = "5.4.6";
				r.lastResult = "Alias loop at " + r.address;
				return;
			}
			r.status = QueuedRecipient.Status.EXPANDED;
			r.lastStatus = "2.0.0";
			r.lastResult = "expanded to " + target.members;
			if (r.wants(QueuedRecipient.Notify.SUCCESS)) {
				succeeded.add(r);
				actions.add("expanded");
			}
			for (String m : target.members) {
				MailAddress a;
				try {
					a = m.indexOf('@') > 0 ? MailAddress.parse(m, true) : new MailAddress(m, r.address.getDomain());
				} catch (IllegalArgumentException ex) {
					LOG.log(Level.WARNING, "Invalid alias member " + m);
					continue;
				}
				QueuedRecipient q = new QueuedRecipient(a, r.orcpt != null ? r.orcpt : "rfc822;" + r.address,
						r.notify == null ? null : EnumSet.copyOf(r.notify));
				if (q.notify != null) {
					q.notify.remove(QueuedRecipient.Notify.SUCCESS); // reported as "expanded"
					if (q.notify.isEmpty()) {
						q.notify.add(QueuedRecipient.Notify.NEVER);
					}
				}
				q.depth = r.depth + 1;
				e.recipients.add(q);
			}
			return;
		}
		try {
			local.deliver(e, content, r.address, target);
			r.status = QueuedRecipient.Status.DELIVERED;
			r.lastStatus = "2.0.0";
			r.lastResult = "delivered to " + target.user;
			if (r.wants(QueuedRecipient.Notify.SUCCESS)) {
				succeeded.add(r);
				actions.add("delivered");
			}
		} catch (IOException ex) {
			r.lastStatus = "4.2.0";
			r.lastResult = "Local delivery failed: " + ex.getMessage();
			retryLater(e, r, now);
		}
	}

	/** Queue a DSN to the sender of {@code e} about some recipients. */
	private void notify(QueueEntry e, FileSource content, DsnBuilder.Kind kind, List<QueuedRecipient> rcpts,
			List<String> actions) {
		if (rcpts.isEmpty()) {
			return;
		}
		List<String> acts = actions;
		if (acts == null) {
			acts = new ArrayList<>();
			for (int i = 0; i < rcpts.size(); i++) {
				acts.add(kind.action);
			}
		}
		try {
			QueueEntry d = new QueueEntry(newId());
			d.from = null; // never bounce a bounce (RFC 5321 section 4.5.5)
			FileSource in = incoming(d.id);
			DsnBuilder.Written w = DsnBuilder.write(in, config, e, content, kind, rcpts, acts, e.created + config.getMaxAge());
			d.size = dkimSign(d.id, in) ? in.length() : w.size;
			d.smtpUtf8 = w.utf8;
			d.body = QueueEntry.Body.EIGHT_BIT;
			d.recipients.add(new QueuedRecipient(e.from, null, EnumSet.of(QueuedRecipient.Notify.NEVER)));
			commit(d, in);
		} catch (IOException ex) {
			LOG.log(Level.ERROR, "Can't create a delivery status notification for " + e.id, ex);
		}
	}
}
