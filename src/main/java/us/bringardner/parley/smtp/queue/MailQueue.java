package us.bringardner.parley.smtp.queue;

import us.bringardner.parley.io.IoUtils;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
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
import us.bringardner.parley.mail.store.MailLocks;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.net.lock.LockDomain;
import us.bringardner.parley.net.lock.NamedLock;
import us.bringardner.parley.net.lock.Sharing;
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
 * <p>
 * Servers may share the queue directory (see {@code parley.mail.sharedStore} in
 * {@link MailLocks}): when the directory is under a maildrop root with a lock domain, each
 * delivery pass holds the entry's lock {@code queue/<dir>/<id>} (an entry another server is
 * working on is skipped, not waited for) and starts from the envelope on disk, so a message is
 * delivered by one server at a time and no server overwrites another's progress. A shared queue
 * looks at the directory every few seconds for messages other servers accepted, and only
 * removes leftover temporary files when they are old enough that no server can still be
 * writing them.
 */
public class MailQueue {

	private static final System.Logger LOG = System.getLogger(MailQueue.class.getName());
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final AtomicLong SEQUENCE = new AtomicLong();
	/** Alias expansion deeper than this is a loop. */
	private static final int MAX_ALIAS_DEPTH = 10;
	/** A shared queue's temporary file this old was left by a server that stopped. */
	static final long STALE_MILLIS = 60 * 60 * 1000L;

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
	/** The lock domain of the queue directory while running, or null (no locks). */
	private volatile LockDomain domain;
	/** Entries {@link #flush()} asked for, kept until their next pass reloads them. */
	private final Set<String> flushRequested = ConcurrentHashMap.newKeySet();
	/** Damaged envelopes, reported once. */
	private final Set<String> damaged = ConcurrentHashMap.newKeySet();
	private volatile long syncMillis = 5000;
	/** How long stop() waits for deliveries under way before returning (they still finish). */
	volatile long stopWaitMillis = 30_000;
	private long lastSync;

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
		boolean ok = false;
		try {
			if (!dir.exists() && !dir.mkdirs()) {
				throw new IOException("Can't create the queue directory " + dir.getAbsolutePath());
			}
			LockDomain d = MailboxRegistry.get().domainOf(dir);
			if (d != null) {
				domain = MailLocks.acquire(d.root()); // our own reference, released by stop()
			}
			syncWithDirectory(true);
			ok = true;
		} finally {
			if (!ok) {
				users--;
				releaseDomain();
			}
		}
		lastSync = System.currentTimeMillis();
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
		ExecutorService w = workers;
		boolean done = true;
		if (w != null) {
			w.shutdown();
			try {
				done = w.awaitTermination(stopWaitMillis, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				done = false;
			}
		}
		if (done) {
			releaseDomain();
			return;
		}
		// a delivery is still under way (a slow remote server): its entry's lock must stay held
		// (leases renewed) until it ends, or another server could take the entry over meanwhile
		LockDomain d = domain;
		domain = null;
		LOG.log(Level.WARNING, "Queue workers are still delivering; the queue's locks are kept until they finish");
		Thread t = new Thread(() -> {
			try {
				while (!w.awaitTermination(1, TimeUnit.MINUTES)) {
					// still delivering
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			} finally {
				if (d != null) {
					MailLocks.release(d);
				}
			}
		}, "SmtpQueueStop");
		t.setDaemon(true);
		t.start();
	}

	private void releaseDomain() {
		LockDomain d = domain;
		domain = null;
		if (d != null) {
			MailLocks.release(d);
		}
	}

	/** True if other servers may use this queue's directory (a lock domain that isn't OFF). */
	public boolean isShared() {
		LockDomain d = domain;
		return d != null && d.sharing() != Sharing.OFF;
	}

	/** How often a shared queue looks at the directory for other servers' messages. */
	public void setSyncInterval(long millis) {
		this.syncMillis = Math.max(1, millis);
	}

	/**
	 * Bring the entries in line with the directory: load envelopes this queue doesn't know yet
	 * (other servers' messages, or all of them at start), drop entries whose envelope is gone
	 * (delivered by another server) and remove leftover temporary files and message contents
	 * without an envelope (a commit cut short by a crash). Files are only removed when no other
	 * server can be using them: unshared, everything left over from before a crash goes at
	 * start; shared, only files older than an hour.
	 */
	void syncWithDirectory(boolean starting) throws IOException {
		FileSource[] list = dir.listFiles();
		if (list == null) {
			return;
		}
		boolean shared = isShared();
		long now = System.currentTimeMillis();
		Set<String> onDisk = new HashSet<>();
		java.util.Map<String, FileSource> contents = new java.util.HashMap<>();
		for (FileSource f : list) {
			String name = f.getName();
			if (!name.startsWith(".") && name.endsWith(".eml")) {
				contents.put(name.substring(0, name.length() - 4), f);
			}
			if (name.startsWith(".")) {
				if (shared ? isStale(f, now) : starting) {
					f.delete(); // an incomplete message or envelope from before a crash
				}
			} else if (name.endsWith(".env")) {
				String id = name.substring(0, name.length() - 4);
				onDisk.add(id);
				if (entries.containsKey(id)) {
					continue;
				}
				try {
					QueueEntry e = QueueEntry.read(f);
					if (content(e.id).exists()) {
						entries.putIfAbsent(e.id, e);
						damaged.remove(name);
					} else if (!shared) {
						f.delete();
					}
				} catch (FileNotFoundException | java.nio.file.NoSuchFileException gone) {
					// delivered and removed by another server since the listing
				} catch (IOException e) {
					if (damaged.add(name)) {
						LOG.log(Level.WARNING, "Skipping damaged queue file " + name, e);
					}
				}
			}
		}
		// content with no envelope: a commit that stopped between the two (a crash); the sender
		// never got its 250, so it sends again. Removed like the temporary files: unshared at start,
		// shared once over an hour old (a commit in progress takes a moment)
		// shared also under the entry's lock, so an envelope another server is replacing (missing for
		// a moment on a store without an atomic replace) is never taken for one that is gone
		LockDomain d = domain;
		for (Map.Entry<String, FileSource> c : contents.entrySet()) {
			String id = c.getKey();
			if (onDisk.contains(id) || entries.containsKey(id) || !(shared ? isStale(c.getValue(), now) : starting)) {
				continue;
			}
			NamedLock l = d == null ? null : d.request(lockName(d, id)).exclusive().reentrant(false).tryAcquire();
			if (d != null && l == null) {
				continue;
			}
			try {
				if (!envelope(id).exists()) {
					c.getValue().delete();
				}
			} finally {
				if (l != null) {
					l.close();
				}
			}
		}
		if (!starting) {
			for (String id : new ArrayList<>(entries.keySet())) {
				if (!onDisk.contains(id) && !active.contains(id) && !envelope(id).exists()) {
					entries.remove(id);
				}
			}
		}
	}

	private static boolean isStale(FileSource f, long now) {
		try {
			return now - f.lastModified() > STALE_MILLIS;
		} catch (IOException e) {
			return false;
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
		if (domain != null) {
			flushRequested.addAll(entries.keySet()); // each pass starts from the envelope on disk
		}
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
			if (isShared() && now - lastSync >= syncMillis) {
				lastSync = now;
				try {
					syncWithDirectory(false);
				} catch (IOException | RuntimeException ex) {
					LOG.log(Level.DEBUG, "Can't look at the queue directory", ex);
				}
			}
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
			try (InputStream in = IoUtils.buffered(incoming.getInputStream())) {
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
			try (InputStream in = IoUtils.buffered(incoming.getInputStream())) {
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
	void arcSeal(QueueEntry e, FileSource content, NamedLock entryLock) {
		Arc arc = config.getArc();
		ArcSealer sealer = arc.sealer(config.getDkim(), config.getHostname());
		if (sealer == null) {
			return;
		}
		try {
			String set;
			try (InputStream in = IoUtils.buffered(content.getInputStream())) {
				set = sealer.seal(in, config.getHostname());
			}
			synchronized (e) {
				if (set != null) {
					HeaderRewriter.prepend(content, incoming(e.id + "s"), set);
					e.size = content.length();
				}
				e.arcSealed = true;
				e.write(envelope(e.id), entryLock);
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
		try (OutputStream out = IoUtils.buffered(in.getOutputStream());
				SmtpStreams.CrlfOutputStream crlf = new SmtpStreams.CrlfOutputStream(out);
				InputStream src = IoUtils.buffered(content)) {
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

	/** The lock name of an entry: the same on every server sharing the queue. */
	private String lockName(LockDomain d, String id) throws IOException {
		return MailboxRegistry.lockName("queue", d, dir) + "/" + id;
	}

	/**
	 * One delivery pass over an entry's due recipients. With a lock domain, under the entry's
	 * lock (skipped if another server holds it) and from the envelope as it is on disk.
	 */
	void process(QueueEntry e) throws IOException {
		LockDomain d = domain;
		if (d == null) {
			process(e, null);
			return;
		}
		NamedLock l = d.request(lockName(d, e.id)).exclusive().reentrant(false).tryAcquire();
		if (l == null) {
			return; // another server is delivering it; we'll see its progress next time
		}
		try {
			QueueEntry cur = reload(e);
			if (cur == null) {
				return;
			}
			if (flushRequested.remove(cur.id)) {
				synchronized (cur) {
					for (QueuedRecipient r : cur.recipients) {
						if (r.status == QueuedRecipient.Status.PENDING) {
							r.nextAttempt = 0;
						}
					}
				}
			}
			if (cur.nextAttempt() > System.currentTimeMillis()) {
				return; // another server tried it since we looked
			}
			process(cur, l);
		} finally {
			l.close();
		}
	}

	/**
	 * The entry as saved (another server may have worked on it), now in the entries; null if it
	 * is gone (delivered, or half removed, which is finished here).
	 */
	private QueueEntry reload(QueueEntry e) throws IOException {
		FileSource env = envelope(e.id);
		QueueEntry cur;
		try {
			cur = QueueEntry.read(env);
		} catch (IOException ex) {
			if (env.exists()) {
				throw ex;
			}
			entries.remove(e.id);
			return null;
		}
		if (!content(e.id).exists()) {
			env.delete();
			entries.remove(e.id);
			return null;
		}
		entries.put(cur.id, cur);
		return cur;
	}

	private void process(QueueEntry e, NamedLock entryLock) throws IOException {
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
			arcSeal(e, content, entryLock);
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
				e.write(envelope(e.id), entryLock);
			} else {
				if (entryLock != null) {
					entryLock.checkValid();
				}
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
