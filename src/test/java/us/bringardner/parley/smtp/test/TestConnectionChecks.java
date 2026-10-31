package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static us.bringardner.parley.mail.test.MailTestSupport.ACL_FILE;
import static us.bringardner.parley.mail.test.MailTestSupport.deleteAll;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.ILogger.Level;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.smtp.abuse.ConnectionChecks;
import us.bringardner.parley.smtp.abuse.Dnsbl;
import us.bringardner.parley.smtp.abuse.RateLimiter;
import us.bringardner.parley.smtp.server.SmtpServer;

/** The checks of a client before any mail: block lists, HELO, pregreet and rate limits. */
public class TestConnectionChecks {

	private static SmtpServer b;
	private static FileSource rootB;

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("parley.mail.smtp." + FileBasedAcl.PROP_FILE_NAME, ACL_FILE);
		System.setProperty("parley.mail.smtp." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		rootB = FileSourceFactory.getDefaultFactory().createTempDirectory("ccB");
		b = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		b.setMaildropRoot(rootB);
		MailStoreSetup.setUp(rootB, "mx.b.test", "b.test");
		b.setHostname("mx.b.test");
		b.getDeliveryConfig().getLocalDomains().clear();
		b.addLocalDomain("b.test");
		b.getLogger().setLevel(Level.ERROR);
		b.startAndWait(10000);
	}

	@AfterAll
	public static void stop() throws Exception {
		if (b != null) {
			b.stop();
		}
		deleteAll(rootB);
	}

	@AfterEach
	public void reset() {
		ConnectionChecks c = b.getConnectionChecks();
		c.setLogOnly(false);
		c.setCheckHelo(false);
		c.setRequireReverseDns(false);
		c.setPregreetMillis(0);
		c.setMaxConnectionsPerMinute(0);
		c.setMaxConcurrentPerAddress(0);
		c.setMaxMessagesPerMinute(0);
		c.setMaxRecipientsPerMinute(0);
		c.getDnsbl().setZones(new ArrayList<>());
		c.resetCounters();
	}

	private static List<Object> a(String address) {
		Map<String, Object> m = new HashMap<>();
		m.put("A", address);
		return Arrays.asList(m);
	}

	@Test
	public void dnsblListsOnlyRealListings() throws Exception {
		Map<String, Object> zone = new HashMap<>();
		zone.put("1.2.0.192.bl.test", a("127.0.0.2"));
		zone.put("9.2.0.192.bl.test", a("127.255.255.254")); // the list refusing the query
		zone.put("2.2.0.192.second.test", a("127.0.0.4"));
		zone.put("3.2.0.192.bl.test", Arrays.asList("TIMEOUT"));
		TestSpfSuite.Zone dns = new TestSpfSuite.Zone(zone);

		Dnsbl d = new Dnsbl();
		assertNull(d.listedIn(InetAddress.getByName("192.0.2.1"), dns), "no zones");
		d.setZones(Arrays.asList("bl.test.", " second.test "));
		assertEquals("bl.test", d.listedIn(InetAddress.getByName("192.0.2.1"), dns));
		assertEquals("second.test", d.listedIn(InetAddress.getByName("192.0.2.2"), dns), "the second zone");
		assertNull(d.listedIn(InetAddress.getByName("192.0.2.9"), dns), "127.255.255.x is not a listing");
		assertNull(d.listedIn(InetAddress.getByName("192.0.2.3"), dns), "a failed lookup is not a listing");
		assertNull(d.listedIn(InetAddress.getByName("192.0.2.77"), dns), "not listed");
		assertNull(d.listedIn(InetAddress.getByName("127.0.0.1"), dns), "a loopback address is never asked");
		assertNull(d.listedIn(InetAddress.getByName("10.0.0.1"), dns), "a private address is never asked");
	}

	@Test
	public void checkBlockListGivesTheRefusal() throws Exception {
		Map<String, Object> zone = new HashMap<>();
		zone.put("1.2.0.192.bl.test", a("127.0.0.2"));
		ConnectionChecks c = new ConnectionChecks();
		c.getDnsbl().setZones(Arrays.asList("bl.test"));
		ConnectionChecks.Refusal r = c.checkBlockList(InetAddress.getByName("192.0.2.1"), new TestSpfSuite.Zone(zone));
		assertNotNull(r);
		assertEquals(554, r.code);
		assertEquals("5.7.1", r.enhanced);
		assertTrue(r.text.contains("[192.0.2.1] blocked using bl.test"), r.text);
	}

	@Test
	public void rateLimiterSlidesItsWindow() {
		RateLimiter r = new RateLimiter(1000);
		long t = 10_000;
		assertTrue(r.tryAcquire("x", 2, t));
		assertTrue(r.tryAcquire("x", 2, t + 100));
		assertFalse(r.tryAcquire("x", 2, t + 200), "over the limit");
		assertTrue(r.tryAcquire("y", 2, t + 200), "another key");
		assertTrue(r.tryAcquire("x", 2, t + 1100), "the first event has left the window");
		assertTrue(r.tryAcquire("x", 0, t), "no limit");
	}

	@Test
	public void aPrivateClientIsNeverBlocked() throws Exception {
		b.getConnectionChecks().getDnsbl().setZones(Arrays.asList("bl.test"));
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			assertTrue(c.greeting.startsWith("220 "), c.greeting);
		}
	}

	@Test
	public void connectionRate() throws Exception {
		b.getConnectionChecks().setMaxConnectionsPerMinute(2);
		for (int i = 0; i < 2; i++) {
			try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
				assertTrue(c.greeting.startsWith("220 "), c.greeting);
			}
		}
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			assertTrue(c.greeting.startsWith("421 4.7.0 "), c.greeting);
		}
	}

	@Test
	public void concurrentConnections() throws Exception {
		b.getConnectionChecks().setMaxConcurrentPerAddress(1);
		try (TestSmtpServer.Client first = new TestSmtpServer.Client(b.getLocalPort())) {
			assertTrue(first.greeting.startsWith("220 "), first.greeting);
			try (TestSmtpServer.Client second = new TestSmtpServer.Client(b.getLocalPort())) {
				assertTrue(second.greeting.startsWith("421 4.7.0 "), second.greeting);
			}
		}
		// the first one ends, so the count falls and a new client is let in
		TestSmtpServer.waitFor(() -> {
			try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
				return c.greeting.startsWith("220 ");
			} catch (Exception e) {
				return false;
			}
		}, 10000, "a connection after the first ended");
	}

	@Test
	public void heloNames() throws Exception {
		b.getConnectionChecks().setCheckHelo(true);
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			assertTrue(c.cmd("EHLO localhost").startsWith("550 5.7.1 "), "not fully qualified");
			assertTrue(c.cmd("EHLO mx.b.test").startsWith("550 5.7.1 "), "our own name");
			assertTrue(c.cmd("HELO B.TEST").startsWith("550 5.7.1 "), "our own domain");
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<a@client.example>", "250");
		}
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO [192.0.2.7]", "250"); // an address literal
		}
	}

	@Test
	public void logOnlyRefusesNothing() throws Exception {
		b.getConnectionChecks().setCheckHelo(true);
		b.getConnectionChecks().setMaxConnectionsPerMinute(1);
		b.getConnectionChecks().setLogOnly(true);
		for (int i = 0; i < 3; i++) {
			try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
				assertTrue(c.greeting.startsWith("220 "), c.greeting);
				c.ok("EHLO localhost", "250");
			}
		}
	}

	@Test
	public void pregreet() throws Exception {
		b.getConnectionChecks().setPregreetMillis(400);
		// a polite client waits for the greeting
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			assertTrue(c.greeting.startsWith("220 "), c.greeting);
		}
		// an impatient one talks first
		try (java.net.Socket s = new java.net.Socket("localhost", b.getLocalPort())) {
			s.setSoTimeout(10000);
			s.getOutputStream().write("EHLO client.example\r\n".getBytes());
			s.getOutputStream().flush();
			String reply = new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream())).readLine();
			assertNotNull(reply);
			assertTrue(reply.startsWith("554 5.5.0 "), reply);
		}
	}

	@Test
	public void messageRate() throws Exception {
		b.getConnectionChecks().setMaxMessagesPerMinute(2);
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<a@client.example>", "250");
			c.ok("RSET", "250");
			c.ok("MAIL FROM:<a@client.example>", "250");
			c.ok("RSET", "250");
			assertTrue(c.cmd("MAIL FROM:<a@client.example>").startsWith("450 4.7.1 "));
		}
	}

	@Test
	public void recipientRate() throws Exception {
		b.getConnectionChecks().setMaxRecipientsPerMinute(2);
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<a@client.example>", "250");
			c.ok("RCPT TO:<team1@b.test>", "250");
			c.ok("RCPT TO:<team1@b.test>", "250");
			assertTrue(c.cmd("RCPT TO:<team1@b.test>").startsWith("450 4.7.1 "));
		}
	}
}
