package us.bringardner.parley.smtp.test;

import us.bringardner.parley.mail.test.MailTestSupport;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

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
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.smtp.dmarc.DmarcChecker;
import us.bringardner.parley.smtp.dmarc.DmarcRecord.Policy;
import us.bringardner.parley.smtp.dmarc.DmarcReporter;
import us.bringardner.parley.smtp.dmarc.DmarcResult;
import us.bringardner.parley.smtp.spf.SpfChecker;
import us.bringardner.parley.smtp.spf.SpfResult;

/**
 * A DMARC report directory shared by servers: each keeps logs of its own, one server sends
 * at a time, and the servers together send about once an interval.
 */
public class TestSharedDmarcReports {

	private static String before;
	private static FileSource root;
	private static LockDomain domain;
	private static Locks other;
	private static LockDomain otherDomain;

	private final Map<String, String> txt = new HashMap<>();
	private final List<String> sent1 = Collections.synchronizedList(new ArrayList<>());
	private final List<String> sent2 = Collections.synchronizedList(new ArrayList<>());
	private final AtomicLong now = new AtomicLong(1_790_000_000_000L);
	private FileSource dir;
	private DmarcReporter r1;
	private DmarcReporter r2;

	@BeforeAll
	public static void setUpStore() throws Exception {
		before = System.getProperty(MailLocks.SHARED_STORE_PROPERTY);
		System.setProperty(MailLocks.SHARED_STORE_PROPERTY, "cluster");
		root = FileSourceFactory.getDefaultFactory().createTempDirectory("sharedDmarc");
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
		MailTestSupport.deleteAll(root);
		if (before == null) {
			System.clearProperty(MailLocks.SHARED_STORE_PROPERTY);
		} else {
			System.setProperty(MailLocks.SHARED_STORE_PROPERTY, before);
		}
	}

	@BeforeEach
	public void setUp() throws Exception {
		dir = root.getChild(".dmarc-reports");
		MailTestSupport.deleteAll(dir);
		txt.put("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc@example.com");
		r1 = reporter(sent1);
		r2 = reporter(sent2);
	}

	@AfterEach
	public void tearDown() {
		r1.stop();
		r2.stop();
	}

	private DmarcReporter reporter(List<String> sent) throws IOException {
		DmarcReporter r = new DmarcReporter();
		r.setAggregate(true);
		r.setOrgName("mx.b.test");
		r.setEmail("postmaster@b.test");
		r.setHostname("mx.b.test");
		r.setClock(now::get);
		r.start(dir, (from, to, message) -> sent.add(new String(message, StandardCharsets.UTF_8)), TestDkim.keys(txt)::txt, null);
		return r;
	}

	private void evaluate(DmarcReporter r) throws Exception {
		SpfResult spf = spf();
		DmarcResult d = new DmarcChecker(TestDkim.keys(txt)::txt, null).check(Collections.singletonList("joe@example.com"), spf,
				Collections.emptyList());
		HeaderFields h = HeaderFields.read(new ByteArrayInputStream("From: joe@example.com\r\n\r\nx\r\n".getBytes(StandardCharsets.UTF_8)));
		r.evaluated(d, InetAddress.getByName("192.0.2.7"), "bounce@example.com", spf, Collections.emptyList(), Policy.NONE, h,
				"mx.b.test; spf=pass");
	}

	private static SpfResult spf() throws Exception {
		Map<String, Object> zone = new HashMap<>();
		Map<String, Object> rec = new HashMap<>();
		rec.put("SPF", "v=spf1 +all");
		zone.put("example.com", Collections.singletonList(rec));
		return new SpfChecker(new TestSpfSuite.Zone(zone), "mx.b.test").checkMailFrom(InetAddress.getByName("192.0.2.7"),
				"bounce@example.com", "client.test");
	}

	private int logs() throws IOException {
		int n = 0;
		if (dir.exists()) {
			for (FileSource f : dir.listFiles()) {
				if (f.getName().endsWith(".log")) {
					n++;
				}
			}
		}
		return n;
	}

	private String sendLock() throws IOException {
		return MailboxRegistry.lockName("dmarc", otherDomain, dir) + "/send";
	}

	@Test
	public void oneReportHoldsEveryServersEvaluations() throws Exception {
		evaluate(r1);
		evaluate(r1);
		evaluate(r2);
		assertEquals(2, logs(), "a log per server");
		now.addAndGet(3_600_000);
		assertEquals(1, r2.flush());
		assertEquals(1, sent2.size());
		String xml = TestDmarcReports.xml(sent2.get(0));
		assertTrue(xml.contains("<count>3</count>"), "both servers' evaluations: " + xml);
		assertEquals(0, r1.flush(), "nothing left to send");
		assertTrue(sent1.isEmpty());
		assertEquals(0, logs());
	}

	@Test
	public void aServerSendingLeavesTheOthersOut() throws Exception {
		evaluate(r1);
		NamedLock held = otherDomain.tryLock(sendLock(), Mode.EXCLUSIVE);
		assertNotNull(held);
		try {
			assertEquals(0, r1.flush(), "another server is sending");
			assertEquals(1, logs(), "and the evaluations wait");
		} finally {
			held.close();
		}
		assertEquals(1, r1.flush());
	}

	@Test
	public void theTimerSendsOnceAnIntervalAmongTheServers() throws Exception {
		evaluate(r1);
		now.addAndGet(r1.getIntervalMillis());
		assertEquals(1, r1.flushIfDue());
		evaluate(r2);
		now.addAndGet(60_000);
		assertEquals(0, r2.flushIfDue(), "r1 sent a minute ago");
		assertEquals(1, logs());
		now.addAndGet(r2.getIntervalMillis());
		assertEquals(1, r2.flushIfDue());
		evaluate(r1);
		assertEquals(1, r1.flush(), "an explicit flush doesn't wait for the interval");
	}
}
