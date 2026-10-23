package us.bringardner.parley.smtp.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static us.bringardner.parley.mail.test.MailTestSupport.deleteAll;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.FileBasedAcl.FileBasedPrincipal;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.smtp.MailAddress;

/**
 * Queue events (for an application's history of the queue), the administrator's actions on a
 * message (delete, retry) and local delivery with several local domains (virtual domains).
 */
public class TestQueueEvents {

	private FileSource root;
	private MailQueue queue;
	private final List<QueueEvent> events = new CopyOnWriteArrayList<>();

	/** Users by name; a user may have a maildrop parameter. */
	private static final class Users implements IAccessControlList {
		final Map<String, IPrincipal> users = new HashMap<>();

		void add(String name, String maildrop) {
			FileBasedPrincipal p = new FileBasedPrincipal(name);
			if (maildrop != null) {
				p.setParameter(LocalDelivery.PARAMETER_MAILDROP, maildrop);
			}
			users.put(name, p);
		}

		@Override
		public void initialize(IServer server) {
		}

		@Override
		public boolean checkPermission(IPrincipal user, IPermission action) {
			return false;
		}

		@Override
		public IPrincipal getPrincipal(String user) {
			return users.get(user);
		}
	}

	@BeforeEach
	public void setUp() throws IOException {
		root = FileSourceFactory.getDefaultFactory().createTempDirectory("queueEvents");
		Users users = new Users();
		users.add("tony@a.test", "a.test/tony");
		users.add("joe", null); // no domain: every local domain
		DeliveryConfig c = new DeliveryConfig();
		c.setMaildropRoot(root);
		c.setAccessControl(users);
		c.getLocalDomains().clear();
		c.addLocalDomain("a.test");
		c.addLocalDomain("b.test");
		c.addAlias("sales@b.test", "tony@a.test");
		c.setRetrySchedule(60_000);
		queue = new MailQueue(root.getChild(".smtp-queue"), c);
		queue.addQueueListener(events::add);
	}

	@AfterEach
	public void tearDown() throws IOException {
		queue.stop();
		deleteAll(root);
	}

	private QueueEntry send(String... to) throws IOException {
		List<MailAddress> rcpts = new ArrayList<>();
		for (String a : to) {
			rcpts.add(MailAddress.parse(a, true));
		}
		// from <> so failures make no bounce
		return queue.enqueue(null, rcpts, new ByteArrayInputStream("Subject: hi\r\n\r\nbody\r\n".getBytes(StandardCharsets.UTF_8)),
				false);
	}

	private QueueEvent waitFor(QueueEvent.Type type, String id) throws InterruptedException {
		long end = System.currentTimeMillis() + 20000;
		while (System.currentTimeMillis() < end) {
			for (QueueEvent e : events) {
				if (e.getType() == type && e.getId().equals(id)) {
					return e;
				}
			}
			Thread.sleep(20);
		}
		throw new AssertionError("No " + type + " event for " + id + ": " + events);
	}

	private Map<String, QueueEvent> byRecipient(String id) {
		return events.stream().filter(e -> e.getId().equals(id) && e.getRecipient() != null)
				.collect(Collectors.toMap(QueueEvent::getRecipient, e -> e, (a, b) -> b));
	}

	@Test
	public void eventsAndVirtualDomains() throws Exception {
		queue.start();
		QueueEntry e = send("tony@a.test", "tony+news@a.test", "tony@b.test", "joe@a.test", "joe@b.test", "sales@b.test");
		QueueEvent queued = waitFor(QueueEvent.Type.QUEUED, e.getId());
		assertEquals(6, queued.getRecipients().size());
		assertEquals("", queued.getFrom());
		waitFor(QueueEvent.Type.COMPLETED, e.getId());

		Map<String, QueueEvent> r = byRecipient(e.getId());
		assertEquals(QueueEvent.Type.DELIVERED, r.get("tony@a.test").getType());
		assertEquals("delivered to tony@a.test", r.get("tony@a.test").getResult());
		assertEquals(QueueEvent.Type.DELIVERED, r.get("tony+news@a.test").getType(), "+detail");
		assertEquals(QueueEvent.Type.FAILED, r.get("tony@b.test").getType(), "tony exists only in a.test");
		assertEquals("5.1.1", r.get("tony@b.test").getStatus());
		assertEquals(QueueEvent.Type.DELIVERED, r.get("joe@a.test").getType(), "a user without a domain");
		assertEquals(QueueEvent.Type.DELIVERED, r.get("joe@b.test").getType());
		assertEquals(QueueEvent.Type.EXPANDED, r.get("sales@b.test").getType(), "a domain's alias");

		assertTrue(root.getChild("a.test").getChild("tony").exists(), "the maildrop parameter is used");
		assertTrue(root.getChild("joe").exists());
		assertNull(queue.getEntry(e.getId()), "gone from the queue");
	}

	@Test
	public void deleteAndRetry() throws Exception {
		// not started: the message stays in the queue
		QueueEntry e = send("joe@a.test");
		assertNotNull(queue.getEntry(e.getId()));
		FileSource content = queue.getContent(e.getId());
		assertNotNull(content);
		assertTrue(content.length() > 0);

		assertTrue(queue.retry(e.getId()));
		assertFalse(queue.retry("nope"));
		assertFalse(queue.delete("nope"));

		assertTrue(queue.delete(e.getId()));
		assertNull(queue.getEntry(e.getId()));
		assertNull(queue.getContent(e.getId()));
		assertFalse(content.exists());
		QueueEvent deleted = waitFor(QueueEvent.Type.DELETED, e.getId());
		assertEquals(List.of("joe@a.test"), deleted.getRecipients());
		assertFalse(queue.delete(e.getId()), "only once");
	}

	@Test
	public void aFailingListenerDoesNoHarm() throws Exception {
		queue.addQueueListener(ev -> {
			throw new IllegalStateException("listener bug");
		});
		queue.start();
		QueueEntry e = send("joe@a.test");
		waitFor(QueueEvent.Type.COMPLETED, e.getId());
		assertEquals(QueueEvent.Type.DELIVERED, byRecipient(e.getId()).get("joe@a.test").getType());
	}
}
