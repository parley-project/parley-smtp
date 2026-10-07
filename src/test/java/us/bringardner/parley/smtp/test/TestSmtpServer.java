package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.ILogger.Level;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.mail.store.MailStore;
import us.bringardner.parley.mail.store.Mailbox;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.smtp.queue.DeliveryConfig;
import us.bringardner.parley.smtp.queue.DeliveryException;
import us.bringardner.parley.smtp.queue.MxResolver;
import us.bringardner.parley.smtp.server.SmtpServer;
import us.bringardner.parley.pop3.test.TestPop3Server;

/**
 * End-to-end tests of SmtpServer over real sockets. Server A (domain a.test)
 * has a relay port and a submission port sharing one queue; server B (domain
 * b.test) is the "remote" MX that A relays to.
 */
public class TestSmtpServer {

	private static final String KEYSTORE = "target/pop3keystore.p12";

	private static SmtpServer a;
	private static SmtpServer submission;
	private static SmtpServer b;
	private static FileSource rootA;
	private static FileSource rootB;
	private static int closedPort;

	@BeforeAll
	public static void start() throws Exception {
		TestPop3Server.makeTestKeystore(new File(KEYSTORE));
		System.setProperty("SmtpServer.KeyStoreName", KEYSTORE);
		System.setProperty("SmtpServer.KeyStorePassword", TestPop3Server.KEYSTORE_PASSWORD);
		System.setProperty("SmtpServer.KeyStoreType", "PKCS12");
		System.setProperty("SmtpServer." + FileBasedAcl.PROP_FILE_NAME, "Pop3TestAcl.txt");
		System.setProperty("SmtpServer." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		FileSourceFactory f = FileSourceFactory.getDefaultFactory();
		rootA = f.createTempDirectory("smtpA");
		rootB = f.createTempDirectory("smtpB");
		try (ServerSocket s = new ServerSocket(0)) {
			closedPort = s.getLocalPort();
		}

		b = server(rootB, "mx.b.test", "b.test");
		b.startAndWait(10000);

		a = server(rootA, "mx.a.test", "a.test");
		DeliveryConfig c = a.getDeliveryConfig();
		c.setResolver((domain, port) -> {
			switch (domain) {
			case "b.test":
				return List.of(new MxResolver.Route("127.0.0.1", b.getLocalPort()));
			case "down.test":
				return List.of(new MxResolver.Route("127.0.0.1", closedPort));
			case "nullmx.test":
				throw DeliveryException.permanent("5.1.10", "The domain " + domain + " accepts no mail (null MX)");
			default:
				throw DeliveryException.permanent("5.1.2", "The domain " + domain + " doesn't exist");
			}
		});
		c.setRetrySchedule(300);
		c.setDelayWarning(600);
		c.setMaxAge(2500);
		c.setConnectTimeout(2000);
		c.addAlias("sales", "tony", "team1@b.test");
		c.addAlias("loop1", "loop2");
		c.addAlias("loop2", "loop1");
		a.startAndWait(10000);

		submission = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		submission.setMaildropRoot(rootA);
		submission.setHostname("mx.a.test");
		submission.setSubmission(true);
		submission.setLoginFailureDelay(0);
		submission.setQueue(a.getQueue());
		submission.getLogger().setLevel(Level.ERROR);
		submission.startAndWait(10000);
	}

	private static SmtpServer server(FileSource root, String host, String domain) throws IOException {
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		s.setMaildropRoot(root);
		s.setHostname(host);
		s.getDeliveryConfig().getLocalDomains().clear();
		s.addLocalDomain(domain);
		s.setLoginFailureDelay(0);
		s.getLogger().setLevel(Level.ERROR);
		s.getSpf().setDns(new TestSpfSuite.Zone(new java.util.HashMap<>())); // SPF without real DNS: every domain has none
		s.getDmarc().setDns(TestDkim.keys(new java.util.HashMap<>())::txt); // nor DMARC: no policy records
		return s;
	}

	@AfterAll
	public static void stop() throws Exception {
		for (SmtpServer s : new SmtpServer[] {submission, a, b}) {
			if (s != null) {
				s.stop();
			}
		}
		deleteAll(rootA);
		deleteAll(rootB);
	}

	private static void deleteAll(FileSource f) throws IOException {
		if (f == null) {
			return;
		}
		if (f.isDirectory()) {
			for (FileSource kid : f.listFiles()) {
				deleteAll(kid);
			}
		}
		f.delete();
	}

	// ------------------------------------------------------------------ helpers

	/** A minimal SMTP client on a raw socket. */
	static final class Client implements Closeable {
		private final int port;
		Socket socket;
		InputStream in;
		OutputStream out;
		final String greeting;

		Client(int port) throws IOException {
			this.port = port;
			socket = new Socket("localhost", port);
			socket.setSoTimeout(30000);
			in = new BufferedInputStream(socket.getInputStream());
			out = socket.getOutputStream();
			greeting = reply();
		}

		String line() throws IOException {
			StringBuilder sb = new StringBuilder();
			java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
			int c;
			while ((c = in.read()) >= 0 && c != '\n') {
				if (c != '\r') {
					b.write(c);
				}
			}
			if (c < 0 && b.size() == 0) {
				return null;
			}
			sb.append(b.toString(StandardCharsets.UTF_8));
			return sb.toString();
		}

		/** A whole reply; multi-line replies are joined with "\n". */
		String reply() throws IOException {
			StringBuilder sb = new StringBuilder();
			String l;
			while ((l = line()) != null) {
				if (sb.length() > 0) {
					sb.append('\n');
				}
				sb.append(l);
				if (l.length() < 4 || l.charAt(3) == ' ') {
					break;
				}
			}
			return l == null && sb.length() == 0 ? null : sb.toString();
		}

		void send(String text) throws IOException {
			out.write((text + "\r\n").getBytes(StandardCharsets.UTF_8));
			out.flush();
		}

		void sendRaw(byte[] b) throws IOException {
			out.write(b);
			out.flush();
		}

		String cmd(String text) throws IOException {
			send(text);
			return reply();
		}

		void ok(String text, String expectedPrefix) throws IOException {
			String r = cmd(text);
			if (!r.startsWith(expectedPrefix)) {
				throw new AssertionError(text + " -> " + r);
			}
		}

		void startTls() throws Exception {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(null, new TrustManager[] {new X509TrustManager() {
				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) {
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) {
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}
			}}, null);
			SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(socket, "localhost", port, true);
			ssl.setUseClientMode(true);
			ssl.startHandshake();
			socket = ssl;
			in = new BufferedInputStream(ssl.getInputStream());
			out = ssl.getOutputStream();
		}

		/** A whole transaction; returns the final reply. */
		String sendMail(String from, String rcpt, String data) throws IOException {
			ok("MAIL FROM:<" + from + ">", "250");
			ok("RCPT TO:<" + rcpt + ">", "250");
			ok("DATA", "354");
			sendRaw(data.getBytes(StandardCharsets.UTF_8));
			send(".");
			return reply();
		}

		@Override
		public void close() throws IOException {
			socket.close();
		}
	}

	static String plain(String user, String password) {
		return Base64.getEncoder().encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
	}

	/** The messages in a user's INBOX directory, as text, in name order. */
	static List<String> inbox(FileSource root, String maildrop) throws IOException {
		List<String> ret = new ArrayList<>();
		FileSource dir = root.getChild(maildrop);
		if (!dir.exists()) {
			return ret;
		}
		List<FileSource> files = new ArrayList<>();
		for (FileSource f : dir.listFiles()) {
			if (!f.getName().startsWith(".") && f.isFile()) {
				files.add(f);
			}
		}
		files.sort((x, y) -> x.getName().compareTo(y.getName()));
		for (FileSource f : files) {
			try (InputStream in = f.getInputStream()) {
				ret.add(new String(in.readAllBytes(), StandardCharsets.UTF_8));
			}
		}
		return ret;
	}

	/**
	 * Empty a maildrop. Waits until the queues have nothing left from earlier
	 * tests, so no late delivery lands in the new maildrop.
	 */
	static void reset(FileSource root, String maildrop) throws IOException {
		try {
			waitFor(() -> (a == null || a.getQueue().getEntries().isEmpty()) && (b == null || b.getQueue().getEntries().isEmpty()),
					30000, "the queues to empty");
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		deleteAll(root.getChild(maildrop));
	}

	static void waitFor(BooleanSupplier condition, long millis, String what) throws InterruptedException {
		long end = System.currentTimeMillis() + millis;
		while (!condition.getAsBoolean()) {
			if (System.currentTimeMillis() > end) {
				throw new AssertionError("Timed out waiting for " + what);
			}
			Thread.sleep(50);
		}
	}

	static int count(FileSource root, String maildrop) {
		try {
			return inbox(root, maildrop).size();
		} catch (IOException e) {
			return -1;
		}
	}

	static String find(List<String> messages, String text) {
		for (String m : messages) {
			if (m.contains(text)) {
				return m;
			}
		}
		return null;
	}

	static final String MESSAGE = "From: x@ext.test\r\nTo: tony@a.test\r\nSubject: hello\r\n\r\nHello Tony\r\n..dot line\r\n";

	// ------------------------------------------------------------------ tests

	@Test
	public void testSession() throws Exception {
		try (Client c = new Client(a.getLocalPort())) {
			assertTrue(c.greeting.startsWith("220 mx.a.test ESMTP"), c.greeting);
			assertTrue(c.cmd("MAIL FROM:<x@ext.test>").startsWith("503 5.5.1"), "HELO first");
			String ehlo = c.cmd("EHLO client.example");
			for (String ext : new String[] {"PIPELINING", "SIZE 52428800", "8BITMIME", "SMTPUTF8", "ENHANCEDSTATUSCODES",
					"CHUNKING", "BINARYMIME", "DSN", "STARTTLS", "AUTH PLAIN LOGIN"}) {
				assertTrue(ehlo.contains("250-" + ext + "\n") || ehlo.endsWith("250 " + ext), ext + " in " + ehlo);
			}
			assertTrue(ehlo.startsWith("250-mx.a.test Hello client.example"), ehlo);
			assertTrue(c.cmd("EHLO").startsWith("501"));
			assertTrue(c.cmd("FOO").startsWith("500 5.5.2"));
			assertTrue(c.cmd("VRFY tony").startsWith("252 2.5.0"));
			assertTrue(c.cmd("EXPN list").startsWith("502"));
			assertTrue(c.cmd("HELP").startsWith("214"));
			assertTrue(c.cmd("NOOP anything").startsWith("250 2.0.0"));
			assertTrue(c.cmd("DATA").startsWith("503 5.5.1"), "DATA before MAIL");
			assertTrue(c.cmd("RCPT TO:<tony@a.test>").startsWith("503 5.5.1"));
			c.ok("MAIL FROM:<x@ext.test>", "250 2.1.0");
			assertTrue(c.cmd("MAIL FROM:<x@ext.test>").startsWith("503"), "nested MAIL");
			assertTrue(c.cmd("DATA").startsWith("554 5.5.1"), "no recipients");
			c.ok("RSET", "250 2.0.0");
			assertTrue(c.cmd("MAIL FROM:<x@ext.test> BOGUS=1").startsWith("555"));
			assertTrue(c.cmd("MAIL FROM:<not an address>").startsWith("501"));
			assertTrue(c.cmd("MAIL FROM:<x@ext.test> SIZE=999999999999").startsWith("552 5.3.4"));
			assertTrue(c.cmd("HELO client.example").startsWith("250 mx.a.test"));
			assertTrue(c.cmd("MAIL FROM:<x@ext.test> SIZE=10").startsWith("555"), "no parameters after HELO");
			assertTrue(c.cmd("QUIT").startsWith("221 2.0.0"));
			assertNull(c.reply(), "closed after QUIT");
		}
		try (Client c = new Client(a.getLocalPort())) {
			assertTrue(c.cmd("GET / HTTP/1.1").startsWith("421"), "not an SMTP client");
			assertNull(c.reply());
		}
	}

	@Test
	public void testLocalDelivery() throws Exception {
		reset(rootA, "tony");
		reset(rootA, "postmaster");
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			assertTrue(c.sendMail("x@ext.test", "tony@a.test", MESSAGE).startsWith("250 2.0.0 Ok: queued as "));
			c.ok("MAIL FROM:<>", "250");
			assertTrue(c.cmd("RCPT TO:<nobody@a.test>").startsWith("550 5.1.1"));
			assertTrue(c.cmd("RCPT TO:<someone@b.test>").startsWith("550 5.7.1"), "not an open relay");
			c.ok("RCPT TO:<Postmaster>", "250 2.1.5");
			c.ok("RCPT TO:<tony+news@A.TEST>", "250"); // subaddress, domain in any case
			c.ok("DATA", "354");
			c.send("Subject: to the postmaster\r\n\r\nhi\r\n.");
			assertTrue(c.reply().startsWith("250"));
		}
		waitFor(() -> count(rootA, "tony") == 2 && count(rootA, "postmaster") == 1, 30000, "local delivery");
		String m = find(inbox(rootA, "tony"), "Subject: hello");
		assertNotNull(m);
		assertTrue(m.startsWith("Return-Path: <x@ext.test>\r\nDelivered-To: tony@a.test\r\nReceived: from client.example ([127.0.0.1])\r\n"
				+ "\tby mx.a.test (Parley) with ESMTP id "), m);
		assertTrue(m.contains("\r\n\tfor <tony@a.test>; "), m);
		assertTrue(m.endsWith("\r\n\r\nHello Tony\r\n.dot line\r\n"), "dot-stuffing removed: " + m);
		String pm = inbox(rootA, "postmaster").get(0);
		assertTrue(pm.startsWith("Return-Path: <>\r\nDelivered-To: postmaster@a.test\r\n"), pm);

		// IMAP sees the same INBOX, with UIDs
		MailStore store = new MailStore(rootA.getChild("tony"), MailboxRegistry.get());
		Mailbox mb = store.open("INBOX");
		try {
			mb.refresh(true); // as SELECT does
			StringBuilder files = new StringBuilder();
			for (FileSource f : rootA.getChild("tony").listFiles()) {
				files.append(f.getName()).append(' ');
			}
			StringBuilder msgs = new StringBuilder();
			for (var info : mb.getMessages()) {
				msgs.append(info.getUid()).append('=').append(info.getName()).append(' ');
			}
			assertEquals(2, mb.count(), "files: " + files + " index: " + msgs);
		} finally {
			MailboxRegistry.get().release(mb);
		}
	}

	@Test
	public void testRelayNetworks() throws Exception {
		SmtpServer trusted = server(rootA, "mx.a.test", "a.test");
		trusted.setQueue(a.getQueue());
		trusted.addRelayNetwork("127.0.0.0/8");
		trusted.startAndWait(10000);
		try (Client c = new Client(trusted.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<app@a.test>", "250");
			c.ok("RCPT TO:<someone@b.test>", "250 2.1.5");
			c.ok("RSET", "250");
		} finally {
			trusted.stop();
		}
	}

	@Test
	public void testSubmission() throws Exception {
		reset(rootB, "team");
		submission.setRequireTls(true);
		try (Client c = new Client(submission.getLocalPort())) {
			String ehlo = c.cmd("EHLO client.example");
			assertFalse(ehlo.contains("AUTH"), "no AUTH before TLS: " + ehlo);
			assertTrue(c.cmd("AUTH PLAIN " + plain("tony", "secret")).startsWith("538 5.7.11"));
			assertTrue(c.cmd("MAIL FROM:<tony@a.test>").startsWith("530 5.7.0"));
			c.ok("STARTTLS", "220 2.0.0");
			c.startTls();
			assertTrue(c.cmd("MAIL FROM:<tony@a.test>").startsWith("503"), "EHLO again after STARTTLS");
			ehlo = c.cmd("EHLO client.example");
			assertTrue(ehlo.contains("AUTH PLAIN LOGIN"), ehlo);
			assertFalse(ehlo.contains("STARTTLS"), ehlo);
			assertTrue(c.cmd("MAIL FROM:<tony@a.test>").startsWith("530 5.7.0 Authentication required"));
			assertTrue(c.cmd("AUTH PLAIN " + plain("tony", "wrong")).startsWith("535 5.7.8"));
			assertTrue(c.cmd("AUTH PLAIN " + plain("reader", "secret")).startsWith("535 5.7.8"), "READ only can't send");
			// AUTH LOGIN
			assertEquals("334 VXNlcm5hbWU6", c.cmd("AUTH LOGIN"));
			assertEquals("334 UGFzc3dvcmQ6", c.cmd(Base64.getEncoder().encodeToString("tony".getBytes())));
			assertTrue(c.cmd(Base64.getEncoder().encodeToString("secret".getBytes())).startsWith("235 2.7.0"));
			assertTrue(c.cmd("AUTH PLAIN x").startsWith("503"), "already authenticated");
			String r = c.sendMail("tony@a.test", "team1@b.test", "From: tony@a.test\r\nTo: team1@b.test\r\nSubject: submitted\r\n\r\nbody\r\n");
			assertTrue(r.startsWith("250 2.0.0"), r);
		} finally {
			submission.setRequireTls(false);
		}
		waitFor(() -> count(rootB, "team") == 1, 30000, "relay to b.test");
		String m = inbox(rootB, "team").get(0);
		assertTrue(m.contains("by mx.b.test (Parley) with ESMTPS id"), "A used STARTTLS with B: " + m);
		assertTrue(m.contains("by mx.a.test (Parley) with ESMTPSA id"), m);
		assertTrue(m.contains("\r\nDate: "), "submission adds Date: " + m);
		assertTrue(m.contains("\r\nMessage-ID: <"), "submission adds Message-ID: " + m);
		try (Client c = new Client(submission.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.send("AUTH PLAIN");
			assertEquals("334 ", c.reply());
			assertTrue(c.cmd("*").startsWith("501"), "cancelled");
			c.send("AUTH PLAIN");
			c.reply();
			assertTrue(c.cmd(plain("tony", "secret")).startsWith("235"));
		}
	}

	@Test
	public void testRelayAndBounces() throws Exception {
		reset(rootA, "tony");
		reset(rootB, "team");
		try (Client c = new Client(submission.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("AUTH PLAIN " + plain("tony", "secret"), "235");
			c.ok("MAIL FROM:<tony@a.test> RET=HDRS ENVID=env+2B1", "250");
			c.ok("RCPT TO:<team1@b.test>", "250");
			c.ok("RCPT TO:<nobody@b.test> ORCPT=rfc822;nobody+40b.test", "250");
			c.ok("RCPT TO:<x@nullmx.test>", "250");
			c.ok("RCPT TO:<x@nosuch.test> NOTIFY=NEVER", "250");
			c.ok("DATA", "354");
			c.send("From: tony@a.test\r\nSubject: mixed\r\n\r\nhi\r\n.");
			assertTrue(c.reply().startsWith("250"));
		}
		try {
			waitFor(() -> count(rootB, "team") == 1 && count(rootA, "tony") == 1, 30000, "delivery and bounce");
		} catch (AssertionError e) {
			throw new AssertionError(e.getMessage() + ": team=" + inbox(rootB, "team") + " tony=" + inbox(rootA, "tony")
					+ " queue=" + a.getQueue().getEntries());
		}
		String dsn = inbox(rootA, "tony").get(0);
		assertTrue(dsn.contains("Return-Path: <>"), dsn);
		assertTrue(dsn.contains("Subject: Undelivered Mail Returned to Sender"), dsn);
		assertTrue(dsn.contains("Content-Type: multipart/report; report-type=delivery-status;"), dsn);
		assertTrue(dsn.contains("Original-Envelope-Id: env+1"), dsn);
		assertTrue(dsn.contains("Final-Recipient: rfc822; nobody@b.test\r\nOriginal-Recipient: rfc822;nobody@b.test\r\n"
				+ "Action: failed\r\nStatus: 5.1.1\r\nRemote-MTA: dns; 127.0.0.1\r\nDiagnostic-Code: smtp; 550 5.1.1"), dsn);
		assertTrue(dsn.contains("Final-Recipient: rfc822; x@nullmx.test\r\nAction: failed\r\nStatus: 5.1.10"), dsn);
		assertFalse(dsn.contains("x@nosuch.test"), "NOTIFY=NEVER");
		assertTrue(dsn.contains("Content-Type: text/rfc822-headers"), "RET=HDRS: " + dsn);
		assertFalse(dsn.contains("\r\n\r\nhi\r\n"), "no body with RET=HDRS");

		// a bounce is never bounced: <> to an unknown domain is dropped
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<>", "250");
			assertTrue(c.cmd("RCPT TO:<x@nosuch.test>").startsWith("550 5.7.1"), "no relay for strangers");
		}
	}

	@Test
	public void testDelayAndExpiry() throws Exception {
		reset(rootA, "jösé");
		try (Client c = new Client(submission.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("AUTH PLAIN " + plain("jösé", "pässwörd"), "235");
			c.ok("MAIL FROM:<jösé@a.test> SMTPUTF8", "250");
			c.ok("RCPT TO:<someone@down.test>", "250");
			c.ok("DATA", "354");
			c.send("Subject: later\r\n\r\nlater\r\n.");
			assertTrue(c.reply().startsWith("250"));
		}
		waitFor(() -> count(rootA, "jösé") == 2, 30000, "delay and failure notices");
		List<String> box = inbox(rootA, "jösé");
		String delay = find(box, "Delayed Mail");
		assertNotNull(delay, box.toString());
		assertTrue(delay.contains("Action: delayed\r\nStatus: 4.4.1"), delay);
		assertTrue(delay.contains("Will-Retry-Until: "), delay);
		assertTrue(delay.contains("message/global-delivery-status") || delay.contains("message/delivery-status"), delay);
		String fail = find(box, "Undelivered Mail");
		assertNotNull(fail);
		assertTrue(fail.contains("Action: failed"), fail);
		assertTrue(fail.contains("Gave up after"), fail);
		assertTrue(fail.contains("Content-Type: message/global"), "the returned UTF-8 message: " + fail);
	}

	@Test
	public void testAliases() throws Exception {
		reset(rootA, "tony");
		reset(rootB, "team");
		reset(rootA, "postmaster");
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			assertTrue(c.sendMail("x@ext.test", "sales@a.test", "Subject: to sales\r\n\r\nhi\r\n").startsWith("250"),
					"aliases may expand to remote addresses");
			assertTrue(c.sendMail("x@ext.test", "loop1@a.test", "Subject: loop\r\n\r\nhi\r\n").startsWith("250"));
		}
		waitFor(() -> count(rootA, "tony") == 1 && count(rootB, "team") == 1, 30000, "alias delivery");
		assertTrue(inbox(rootA, "tony").get(0).contains("Delivered-To: tony@a.test"));
	}

	@Test
	public void testPipeliningAndChunking() throws Exception {
		reset(rootA, "tony");
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			// one write, then the replies in order
			c.sendRaw(("MAIL FROM:<x@ext.test>\r\nRCPT TO:<nobody@a.test>\r\nRCPT TO:<tony@a.test>\r\nDATA\r\n")
					.getBytes(StandardCharsets.US_ASCII));
			assertTrue(c.reply().startsWith("250"));
			assertTrue(c.reply().startsWith("550"));
			assertTrue(c.reply().startsWith("250"));
			assertTrue(c.reply().startsWith("354"));
			c.send("Subject: pipelined\r\n\r\nx\r\n.");
			assertTrue(c.reply().startsWith("250"));

			// BDAT in two chunks; no dot-stuffing
			c.ok("MAIL FROM:<x@ext.test> BODY=BINARYMIME", "250");
			c.ok("RCPT TO:<tony@a.test>", "250");
			assertTrue(c.cmd("DATA").startsWith("503"), "BINARYMIME needs BDAT");
			byte[] part1 = "Subject: chunked\r\n\r\n.not stuffed\n".getBytes(StandardCharsets.US_ASCII);
			byte[] part2 = new byte[] {0, 1, 2, '\r', '\n'};
			c.sendRaw(("BDAT " + part1.length + "\r\n").getBytes(StandardCharsets.US_ASCII));
			c.sendRaw(part1);
			assertTrue(c.reply().startsWith("250 2.0.0 " + part1.length + " octets"));
			c.sendRaw(("BDAT " + part2.length + " LAST\r\n").getBytes(StandardCharsets.US_ASCII));
			c.sendRaw(part2);
			assertTrue(c.reply().startsWith("250 2.0.0 Ok: queued"));

			// BDAT without a transaction: the chunk is skipped
			c.sendRaw("BDAT 5 LAST\r\nhello".getBytes(StandardCharsets.US_ASCII));
			assertTrue(c.reply().startsWith("503"));
			c.ok("NOOP", "250");
		}
		waitFor(() -> count(rootA, "tony") == 2, 30000, "pipelined and chunked delivery");
		String chunked = find(inbox(rootA, "tony"), "chunked");
		assertTrue(chunked.contains("\r\n.not stuffed\r\n"), chunked);
	}

	@Test
	public void testSmugglingAndLimits() throws Exception {
		reset(rootA, "tony");
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<x@ext.test>", "250");
			c.ok("RCPT TO:<tony@a.test>", "250");
			c.ok("DATA", "354");
			// "\n.\n" is not the end of the data, so the "MAIL FROM" after it is content
			c.sendRaw("Subject: smuggle\r\n\r\nfirst\n.\nMAIL FROM:<evil@ext.test>\r\n.\r\n".getBytes(StandardCharsets.US_ASCII));
			String r = c.reply();
			assertTrue(r.startsWith("250"), r);
			c.ok("NOOP", "250");

			// too many hops
			StringBuilder hops = new StringBuilder();
			for (int i = 0; i < 101; i++) {
				hops.append("Received: from x by y; Fri, 02 Oct 2026 12:00:00 -0400\r\n");
			}
			assertTrue(c.sendMail("x@ext.test", "tony@a.test", hops + "Subject: loop\r\n\r\nx\r\n").startsWith("554 5.4.6"));

			// non-ASCII needs SMTPUTF8
			assertTrue(c.cmd("MAIL FROM:<jösé@a.test>").startsWith("553 5.6.7"));
			c.ok("MAIL FROM:<jösé@a.test> SMTPUTF8", "250");
			c.ok("RCPT TO:<tony@a.test>", "250");
			c.ok("RSET", "250");

			long old = a.getMaxMessageSize();
			a.setMaxMessageSize(100);
			try {
				r = c.sendMail("x@ext.test", "tony@a.test", "Subject: big\r\n\r\n" + "x".repeat(200) + "\r\n");
				assertTrue(r.startsWith("552 5.3.4"), r);
			} finally {
				a.setMaxMessageSize(old);
			}
			c.ok("NOOP", "250");
		}
		waitFor(() -> count(rootA, "tony") == 1, 30000, "delivery");
		String m = inbox(rootA, "tony").get(0);
		assertTrue(m.contains("first\r\n.\r\nMAIL FROM:<evil@ext.test>\r\n"), "kept as content: " + m);
	}

	@Test
	public void testQueueSurvivesRestart() throws Exception {
		FileSource root = FileSourceFactory.getDefaultFactory().createTempDirectory("smtpC");
		try {
			SmtpServer c1 = server(root, "mx.c.test", "c.test");
			c1.getDeliveryConfig().setResolver((d, p) -> List.of(new MxResolver.Route("127.0.0.1", closedPort)));
			c1.getDeliveryConfig().setRetrySchedule(60_000);
			c1.getDeliveryConfig().setConnectTimeout(1000);
			c1.addRelayNetwork("127.0.0.1/32");
			c1.startAndWait(10000);
			String id;
			try (Client c = new Client(c1.getLocalPort())) {
				c.ok("EHLO client.example", "250");
				String r = c.sendMail("x@c.test", "someone@far.test", "Subject: wait\r\n\r\nx\r\n");
				id = r.substring(r.lastIndexOf(' ') + 1);
			}
			waitFor(() -> c1.getQueue().getEntries().stream().anyMatch(e -> e.getRecipients().get(0).getAttempts() > 0), 10000,
					"a failed attempt");
			c1.stop();

			SmtpServer c2 = server(root, "mx.c.test", "c.test");
			c2.getDeliveryConfig().setResolver((d, p) -> List.of(new MxResolver.Route("127.0.0.1", closedPort)));
			c2.getDeliveryConfig().setRetrySchedule(60_000);
			c2.startAndWait(10000);
			try {
				assertEquals(1, c2.getQueue().getEntries().size());
				var e = c2.getQueue().getEntries().iterator().next();
				assertEquals(id, e.getId());
				assertEquals("someone@far.test", e.getRecipients().get(0).getAddress().toString());
				assertTrue(e.getRecipients().get(0).getLastResult().contains("Can't connect"), e.getRecipients().get(0).getLastResult());
			} finally {
				c2.stop();
			}
		} finally {
			deleteAll(root);
		}
	}

	@Test
	public void testUtf8Delivery() throws Exception {
		reset(rootB, "jösé");
		try (Client c = new Client(submission.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("AUTH PLAIN " + plain("tony", "secret"), "235");
			c.ok("MAIL FROM:<tony@a.test> SMTPUTF8 BODY=8BITMIME", "250");
			c.ok("RCPT TO:<jösé@b.test>", "250");
			c.ok("DATA", "354");
			c.send("From: tony@a.test\r\nTo: José <jösé@b.test>\r\nSubject: Grüße\r\n\r\nünïcödé\r\n.");
			assertTrue(c.reply().startsWith("250"));
		}
		waitFor(() -> count(rootB, "jösé") == 1, 30000, "UTF-8 relay");
		String m = inbox(rootB, "jösé").get(0);
		assertTrue(m.contains("with UTF8SMTPS id"), m);
		assertTrue(m.contains("Subject: Grüße\r\n\r\nünïcödé\r\n"), m);
	}

	/** A message larger than the test heap (64 MB) is received and delivered by streaming. */
	@Test
	public void testLargeMessage() throws Exception {
		reset(rootA, "tony");
		byte[] line = ("x".repeat(998) + "\r\n").getBytes(StandardCharsets.US_ASCII);
		int lines = 70_000; // about 70 MB
		long old = a.getMaxMessageSize();
		a.setMaxMessageSize(100L * 1024 * 1024);
		try (Client c = new Client(a.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			c.ok("MAIL FROM:<x@ext.test> SIZE=" + (long) line.length * lines, "250");
			c.ok("RCPT TO:<tony@a.test>", "250");
			c.ok("DATA", "354");
			c.sendRaw("Subject: big\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			for (int i = 0; i < lines; i++) {
				c.out.write(line);
			}
			c.send(".");
			String r = c.reply();
			assertTrue(r.startsWith("250"), r);
		} finally {
			a.setMaxMessageSize(old);
		}
		waitFor(() -> {
			try {
				FileSource dir = rootA.getChild("tony");
				if (!dir.exists()) {
					return false;
				}
				for (FileSource f : dir.listFiles()) {
					if (!f.getName().startsWith(".") && f.isFile() && f.length() > (long) line.length * lines) {
						return true;
					}
				}
				return false;
			} catch (IOException e) {
				return false;
			}
		}, 60000, "large delivery");
	}
}
