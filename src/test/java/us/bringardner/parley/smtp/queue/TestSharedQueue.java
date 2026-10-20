package us.bringardner.parley.smtp.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.mail.store.MailLocks;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.net.lock.LockDomain;
import us.bringardner.parley.net.lock.LockOptions;
import us.bringardner.parley.net.lock.Locks;
import us.bringardner.parley.net.lock.Mode;
import us.bringardner.parley.net.lock.NamedLock;
import us.bringardner.parley.net.lock.Sharing;
import us.bringardner.parley.smtp.MailAddress;

/**
 * A queue directory shared by servers ({@code parley.mail.sharedStore=cluster}): each message
 * is delivered once, an entry another server holds is left alone, and no server undoes
 * another's work.
 */
public class TestSharedQueue {

	private static String before;
	private static FileSource root;
	private static LockDomain domain;
	/** Another server: a lock service of its own on the same store. */
	private static Locks other;
	private static LockDomain otherDomain;

	private FileSource dir;
	private MailQueue q1;
	private MailQueue q2;

	@BeforeAll
	public static void setUpStore() throws Exception {
		before = System.getProperty(MailLocks.SHARED_STORE_PROPERTY);
		System.setProperty(MailLocks.SHARED_STORE_PROPERTY, "cluster");
		root = FileSourceFactory.getDefaultFactory().createTempDirectory("sharedQueue");
		domain = MailLocks.acquire(root);
		other = Locks.open(LockOptions.sharing(Sharing.CLUSTER).withOwnerId("other").withLease(Duration.ofSeconds(2), Duration.ofMillis(400)));
		otherDomain = other.domain("mail", root);
	}

	@AfterAll
	public static void tearDownStore() throws Exception {
		if (other != null) {
			other.close();
		}
		MailLocks.release(domain);
		deleteAll(root);
		if (before == null) {
			System.clearProperty(MailLocks.SHARED_STORE_PROPERTY);
		} else {
			System.setProperty(MailLocks.SHARED_STORE_PROPERTY, before);
		}
	}

	@BeforeEach
	public void setUp() throws Exception {
		deleteAll(root.getChild("postmaster"));
		dir = root.getChild(".smtp-queue");
		deleteAll(dir);
		q1 = queue();
		q2 = queue();
	}

	@AfterEach
	public void tearDown() {
		q1.stop();
		q2.stop();
	}

	private MailQueue queue() throws IOException {
		DeliveryConfig c = new DeliveryConfig();
		c.setMaildropRoot(root);
		c.getLocalDomains().clear();
		c.addLocalDomain("s.test");
		c.setRetrySchedule(60_000);
		MailQueue q = new MailQueue(dir, c);
		q.setSyncInterval(50);
		return q;
	}

	@Test
	public void twoQueuesDeliverEachMessageOnce() throws Exception {
		q1.start();
		q2.start();
		assertTrue(q1.isShared() && q2.isShared());
		int n = 20;
		for (int i = 0; i < n; i++) {
			(i % 2 == 0 ? q1 : q2).enqueue(MailAddress.parse("x@far.test", true), List.of(MailAddress.parse("postmaster@s.test", true)),
					new ByteArrayInputStream(("Subject: " + i + "\r\n\r\nbody " + i + "\r\n").getBytes(StandardCharsets.UTF_8)), false);
		}
		waitFor(() -> q1.getEntries().isEmpty() && q2.getEntries().isEmpty() && count() == n, 30000, "delivery");
		Thread.sleep(500);
		assertEquals(n, count(), "nothing delivered twice");
		assertEquals(0, queueFiles(), "the queue is empty");
	}

	@Test
	public void anEntryAnotherServerHoldsIsLeftAlone() throws Exception {
		q1.start();
		String id = MailQueue.newId();
		NamedLock held = otherDomain.tryLock(MailboxRegistry.lockName("queue", otherDomain, dir) + "/" + id, Mode.EXCLUSIVE);
		assertNotNull(held);
		try {
			writeEntry(id, 0); // the other server accepted it
			waitFor(() -> q1.getEntries().stream().anyMatch(e -> e.getId().equals(id)), 10000, "the queue to see it");
			Thread.sleep(800);
			assertEquals(0, count(), "the other server is working on it");
		} finally {
			held.close();
		}
		waitFor(() -> count() == 1 && q1.getEntries().isEmpty(), 10000, "delivery once it lets go");
	}

	@Test
	public void anEntryDeliveredElsewhereIsDropped() throws Exception {
		String id = MailQueue.newId();
		writeEntry(id, Long.MAX_VALUE / 2); // not due: the scheduler leaves it
		q1.start();
		QueueEntry stale = q1.getEntries().stream().filter(e -> e.getId().equals(id)).findFirst().orElse(null);
		assertNotNull(stale, "loaded at start");
		// another server delivers it and removes it
		dir.getChild(id + ".env").delete();
		dir.getChild(id + ".eml").delete();
		for (QueuedRecipient r : stale.recipients) {
			r.nextAttempt = 0; // what this queue (wrongly) believes
		}
		q1.process(stale);
		assertEquals(0, count(), "not delivered from the stale entry");
		assertFalse(q1.getEntries().stream().anyMatch(e -> e.getId().equals(id)));
		assertFalse(dir.getChild(id + ".env").exists(), "and not written back");
	}

	@Test
	public void theEnvelopeOnDiskWins() throws Exception {
		String id = MailQueue.newId();
		writeEntry(id, Long.MAX_VALUE / 2);
		q1.start();
		QueueEntry stale = q1.getEntries().stream().filter(e -> e.getId().equals(id)).findFirst().orElse(null);
		assertNotNull(stale);
		// another server delivered it to some recipients, and keeps the entry for a retry later
		QueueEntry progressed = QueueEntry.read(dir.getChild(id + ".env"));
		progressed.recipients.get(0).status = QueuedRecipient.Status.DELIVERED;
		progressed.recipients.get(0).attempts = 1;
		QueuedRecipient later = new QueuedRecipient(MailAddress.parse("postmaster@s.test", true), null, null);
		later.nextAttempt = Long.MAX_VALUE / 2;
		progressed.recipients.add(later);
		progressed.write(dir.getChild(id + ".env"));
		stale.recipients.get(0).nextAttempt = 0;
		q1.process(stale);
		assertEquals(0, count(), "the delivered recipient isn't delivered again");
		QueueEntry now = QueueEntry.read(dir.getChild(id + ".env"));
		assertEquals(2, now.recipients.size(), "the other server's progress is kept");
		assertEquals(QueuedRecipient.Status.DELIVERED, now.recipients.get(0).status);
	}

	@Test
	public void onlyOldTemporaryFilesAreRemoved() throws Exception {
		dir.mkdirs();
		FileSource fresh = dir.getChild(".in-FRESH.eml");
		FileSource old = dir.getChild(".in-OLD.eml");
		for (FileSource f : new FileSource[] { fresh, old }) {
			try (OutputStream out = f.getOutputStream()) {
				out.write("Subject: x\r\n\r\nx\r\n".getBytes(StandardCharsets.UTF_8));
			}
		}
		old.setLastModified(System.currentTimeMillis() - MailQueue.STALE_MILLIS - 60_000);
		q1.start();
		assertTrue(fresh.exists(), "another server may still be receiving it");
		assertFalse(old.exists(), "left by a server that stopped");
		fresh.delete();
	}

	/**
	 * stop() returns while a slow delivery is still under way, but the entry's lock stays held
	 * until the delivery ends, so another server can't take the entry over meanwhile.
	 */
	@Test
	public void aDeliveryStillUnderWayAtStopKeepsItsLock() throws Exception {
		java.util.concurrent.CountDownLatch delivering = new java.util.concurrent.CountDownLatch(1);
		java.util.concurrent.CountDownLatch finish = new java.util.concurrent.CountDownLatch(1);
		q1.getConfig().setResolver((d, p) -> {
			delivering.countDown();
			try {
				finish.await(20, java.util.concurrent.TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			throw DeliveryException.temporary("4.4.1", "slow");
		});
		q1.stopWaitMillis = 100;
		q1.start();
		MailLocks.release(domain); // the queue's reference is the only one: as when its server stops
		QueueEntry e = q1.enqueue(MailAddress.parse("x@s.test", true), List.of(MailAddress.parse("someone@far.test", true)),
				new ByteArrayInputStream("Subject: slow\r\n\r\nx\r\n".getBytes(StandardCharsets.UTF_8)), false);
		assertTrue(delivering.await(10, java.util.concurrent.TimeUnit.SECONDS), "the delivery started");
		q1.stop();
		String name = MailboxRegistry.lockName("queue", otherDomain, dir) + "/" + e.getId();
		try {
			Thread.sleep(300);
			assertTrue(otherDomain.tryLock(name, Mode.EXCLUSIVE) == null, "still held while it delivers");
		} finally {
			domain = MailLocks.acquire(root);
		}
		finish.countDown();
		waitFor(() -> {
			try {
				NamedLock l = otherDomain.tryLock(name, Mode.EXCLUSIVE);
				if (l != null) {
					l.close();
					return true;
				}
				return false;
			} catch (IOException x) {
				return false;
			}
		}, 10000, "the lock once the delivery ended");
	}

	// ------------------------------------------------------------------ helpers

	/** An entry written as another server would: content, then envelope. */
	private void writeEntry(String id, long nextAttempt) throws IOException {
		dir.mkdirs();
		try (OutputStream out = dir.getChild(id + ".eml").getOutputStream()) {
			out.write("Subject: from the other server\r\n\r\nhi\r\n".getBytes(StandardCharsets.UTF_8));
		}
		QueueEntry e = new QueueEntry(id);
		e.from = MailAddress.parse("x@far.test", true);
		QueuedRecipient r = new QueuedRecipient(MailAddress.parse("postmaster@s.test", true), null, null);
		r.nextAttempt = nextAttempt;
		e.recipients.add(r);
		e.write(dir.getChild(id + ".env"));
	}

	private int queueFiles() throws IOException {
		int n = 0;
		for (FileSource f : dir.listFiles()) {
			if (!f.getName().startsWith(".")) {
				n++;
			}
		}
		return n;
	}

	/** The messages in postmaster's INBOX. */
	private static int count() {
		try {
			FileSource d = root.getChild("postmaster");
			if (!d.exists()) {
				return 0;
			}
			int n = 0;
			for (FileSource f : d.listFiles()) {
				if (!f.getName().startsWith(".") && f.isFile()) {
					n++;
				}
			}
			return n;
		} catch (IOException e) {
			return -1;
		}
	}

	private static void waitFor(BooleanSupplier condition, long millis, String what) throws InterruptedException {
		long end = System.currentTimeMillis() + millis;
		while (!condition.getAsBoolean()) {
			if (System.currentTimeMillis() > end) {
				throw new AssertionError("Timed out waiting for " + what);
			}
			Thread.sleep(50);
		}
	}

	private static void deleteAll(FileSource f) throws IOException {
		if (f == null || !f.exists()) {
			return;
		}
		if (f.isDirectory()) {
			for (FileSource c : f.listFiles()) {
				deleteAll(c);
			}
		}
		f.delete();
	}
}
