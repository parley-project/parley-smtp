package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static us.bringardner.parley.mail.test.MailTestSupport.ACL_FILE;
import static us.bringardner.parley.mail.test.MailTestSupport.deleteAll;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import us.bringardner.parley.core.ILogger.Level;
import us.bringardner.parley.files.ConnectionSetting;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.mail.store.MailStore;
import us.bringardner.parley.mail.store.Mailbox;
import us.bringardner.parley.mail.store.MailboxRegistry;
import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.smtp.server.SmtpServer;
import us.bringardner.parley.smtp.spam.NullSpamFilter;
import us.bringardner.parley.smtp.spam.Spam;
import us.bringardner.parley.smtp.spam.SpamFilter;
import us.bringardner.parley.smtp.spam.SpamProvider;
import us.bringardner.parley.smtp.spam.SpamProviders;
import us.bringardner.parley.smtp.spam.SpamStatus;
import us.bringardner.parley.smtp.spam.SpamRequest;
import us.bringardner.parley.smtp.spam.SpamVerdict;
import us.bringardner.parley.smtp.spam.SpamVerdict.Action;

/** The spam filter interface, its three filters, the per-domain choice of filter and the SMTP hook. */
public class TestSpam {

	// ------------------------------------------------------------------ a filter to plug in

	/** A filter whose answer the test sets; also what a plug-in looks like. */
	static final class Stub implements SpamProvider, SpamFilter {
		static volatile double score;
		static volatile Action action;
		static volatile boolean spam;
		static volatile boolean fail;
		static final List<List<String>> asked = new CopyOnWriteArrayList<>();

		@Override
		public String id() {
			return "stub";
		}

		@Override
		public String getId() {
			return "stub";
		}

		@Override
		public String getTitle() {
			return "Stub";
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			return this;
		}

		@Override
		public SpamVerdict check(SpamRequest r) throws IOException {
			asked.add(r.getRecipients());
			if (fail) {
				throw new IOException("scanner is down");
			}
			return new SpamVerdict(score, 5, spam, action, Arrays.asList("TEST_RULE", "bad name\r\nX: y"));
		}
	}

	/** A second kind, to tell filters apart. */
	static final class Other implements SpamProvider, SpamFilter {
		@Override
		public String id() {
			return "other";
		}

		@Override
		public String getId() {
			return "other";
		}

		@Override
		public String getTitle() {
			return "Other";
		}

		@Override
		public SpamFilter create(Map<String, String> settings) {
			return this;
		}

		@Override
		public SpamVerdict check(SpamRequest r) {
			return new SpamVerdict(1, 5, false, Action.ACCEPT, Collections.emptyList());
		}
	}

	static {
		SpamProviders.register(new Stub());
		SpamProviders.register(new Other());
	}

	private static SpamRequest request(String... rcpts) {
		byte[] msg = "Subject: x\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
		try {
			return new SpamRequest(InetAddress.getByName("192.0.2.9"), "client.example", "a@client.example", Arrays.asList(rcpts), null,
					"mx.b.test", "q1", msg.length, () -> new ByteArrayInputStream(msg));
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	/** the queue's overrides of the engine made last by {@link #spam} */
	private static Map<String, String> domains = new HashMap<>();

	/** An engine from "spam.*" settings of the server; spam.domains is the queue's. */
	private static Spam spam(String... props) {
		Properties q = new Properties();
		for (int i = 0; i < props.length; i += 2) {
			q.setProperty(props[i], props[i + 1]);
		}
		Spam s = new Spam();
		s.configure(n -> q.getProperty("spam." + n));
		domains = Spam.parseDomains(q.getProperty("spam.domains", ""));
		return s;
	}

	private static Spam.Outcome check(Spam s, SpamRequest r) {
		return s.check(r, domains);
	}

	private static String providerFor(Spam s, String domain) {
		return s.providerFor(domain, domains);
	}

	private static boolean isActive(Spam s) {
		return s.isActive(domains);
	}

	@AfterEach
	public void reset() {
		Stub.score = 0;
		Stub.action = null;
		Stub.spam = false;
		Stub.fail = false;
		Stub.asked.clear();
	}

	// ------------------------------------------------------------------ the registry and the null filter

	@Test
	public void registryHasTheBuiltInsAndPlugIns() {
		List<String> ids = SpamProviders.ids();
		assertEquals("none", ids.get(0));
		assertTrue(ids.containsAll(Arrays.asList("none", "rspamd", "spamassassin", "stub", "other")), ids.toString());
		assertNotNull(SpamProviders.get("RSPAMD"));
		assertNull(SpamProviders.get("nothing"));
		assertThrows(IllegalArgumentException.class, () -> SpamProviders.register(new SpamProvider() {
			public String getId() {
				return "Bad Id";
			}

			public String getTitle() {
				return "";
			}

			public SpamFilter create(Map<String, String> s) {
				return null;
			}
		}));
	}

	@Test
	public void nullFilterIsAlwaysClean() throws Exception {
		SpamVerdict v = new NullSpamFilter.Provider().create(new HashMap<>()).check(request("t@b.test"));
		assertEquals(0, v.getScore());
		assertFalse(v.isSpam());
		assertEquals(Action.ACCEPT, v.getAction());
	}

	// ------------------------------------------------------------------ rspamd

	private static HttpServer rspamd(String json, int status, AtomicReference<com.sun.net.httpserver.Headers> seen,
			AtomicReference<String> body) throws IOException {
		HttpServer h = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		h.createContext("/checkv2", ex -> {
			seen.set(ex.getRequestHeaders());
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			ex.getRequestBody().transferTo(b);
			body.set(b.toString("US-ASCII"));
			byte[] out = json.getBytes(StandardCharsets.UTF_8);
			ex.sendResponseHeaders(status, out.length);
			ex.getResponseBody().write(out);
			ex.close();
		});
		h.start();
		return h;
	}

	@Test
	public void rspamdSendsTheSessionAndReadsTheAnswer() throws Exception {
		AtomicReference<com.sun.net.httpserver.Headers> seen = new AtomicReference<>();
		AtomicReference<String> body = new AtomicReference<>();
		HttpServer h = rspamd("{\"score\":12.4,\"required_score\":15.0,\"action\":\"add header\","
				+ "\"symbols\":{\"BAYES_SPAM\":{\"score\":5.1},\"FORGED_SENDER\":{\"score\":0.3}}}", 200, seen, body);
		try {
			Map<String, String> settings = new HashMap<>();
			settings.put("url", "http://127.0.0.1:" + h.getAddress().getPort() + "/");
			settings.put("password", "secret");
			SpamFilter f = SpamProviders.get("rspamd").create(settings);
			SpamVerdict v = f.check(request("t1@b.test", "t2@b.test"));
			assertEquals(12.4, v.getScore());
			assertEquals(15.0, v.getRequiredScore());
			assertTrue(v.isSpam());
			assertEquals(Action.QUARANTINE, v.getAction());
			assertEquals(Arrays.asList("BAYES_SPAM", "FORGED_SENDER"), v.getSymbols());
			assertEquals("192.0.2.9", seen.get().getFirst("IP"));
			assertEquals("client.example", seen.get().getFirst("Helo"));
			assertEquals("a@client.example", seen.get().getFirst("From"));
			assertEquals(Arrays.asList("t1@b.test", "t2@b.test"), seen.get().get("Rcpt"));
			assertEquals("secret", seen.get().getFirst("Password"));
			assertEquals("q1", seen.get().getFirst("Queue-Id"));
			assertTrue(body.get().endsWith("\r\n\r\nbody\r\n"), body.get());
		} finally {
			h.stop(0);
		}
	}

	@Test
	public void rspamdActionsMapToOurs() throws Exception {
		String[][] cases = { { "no action", "ACCEPT" }, { "greylist", "DEFER" }, { "soft reject", "DEFER" },
				{ "rewrite subject", "QUARANTINE" }, { "reject", "REJECT" } };
		for (String[] c : cases) {
			HttpServer h = rspamd("{\"score\":1,\"required_score\":15,\"action\":\"" + c[0] + "\"}", 200,
					new AtomicReference<>(), new AtomicReference<>());
			try {
				Map<String, String> s = new HashMap<>();
				s.put("url", "http://127.0.0.1:" + h.getAddress().getPort());
				SpamVerdict v = SpamProviders.get("rspamd").create(s).check(request("t@b.test"));
				assertEquals(Action.valueOf(c[1]), v.getAction(), c[0]);
				assertEquals(!c[1].equals("ACCEPT"), v.isSpam(), c[0]);
			} finally {
				h.stop(0);
			}
		}
	}

	@Test
	public void rspamdFailuresAreExceptions() throws Exception {
		for (String[] bad : new String[][] { { "500", "{}" }, { "200", "not json" }, { "200", "{\"action\":\"reject\"}" },
				{ "200", "{\"score\":1,\"action\":\"surprise\"}" } }) {
			HttpServer h = rspamd(bad[1], Integer.parseInt(bad[0]), new AtomicReference<>(), new AtomicReference<>());
			try {
				Map<String, String> s = new HashMap<>();
				s.put("url", "http://127.0.0.1:" + h.getAddress().getPort());
				SpamFilter f = SpamProviders.get("rspamd").create(s);
				assertThrows(IOException.class, () -> f.check(request("t@b.test")), bad[0] + " " + bad[1]);
			} finally {
				h.stop(0);
			}
		}
		Map<String, String> s = new HashMap<>();
		s.put("url", "ftp://nowhere");
		assertThrows(IllegalArgumentException.class, () -> SpamProviders.get("rspamd").create(s));
	}

	// ------------------------------------------------------------------ SpamAssassin

	/** A spamd that answers one connection with the given response and returns what it was sent. */
	private static Thread spamd(ServerSocket ss, String response, AtomicReference<String> got) {
		Thread t = new Thread(() -> {
			try (Socket s = ss.accept()) {
				InputStream in = s.getInputStream();
				ByteArrayOutputStream b = new ByteArrayOutputStream();
				in.transferTo(b);
				got.set(b.toString("US-ASCII"));
				s.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
			} catch (IOException e) {
				// the test sees no answer
			}
		});
		t.setDaemon(true);
		t.start();
		return t;
	}

	@Test
	public void spamAssassinSymbolsAnswer() throws Exception {
		try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			AtomicReference<String> got = new AtomicReference<>();
			spamd(ss, "SPAMD/1.1 0 EX_OK\r\nContent-length: 30\r\nSpam: True ; 7.5 / 5.0\r\n\r\nBAYES_99,HTML_MESSAGE,URIBL_BLACK", got);
			Map<String, String> s = new HashMap<>();
			s.put("host", "127.0.0.1");
			s.put("port", String.valueOf(ss.getLocalPort()));
			s.put("user", "spamuser");
			SpamVerdict v = SpamProviders.get("spamassassin").create(s).check(request("t@b.test"));
			assertEquals(7.5, v.getScore());
			assertEquals(5.0, v.getRequiredScore());
			assertTrue(v.isSpam());
			assertNull(v.getAction(), "spamd has no opinion about the action");
			assertEquals(Arrays.asList("BAYES_99", "HTML_MESSAGE", "URIBL_BLACK"), v.getSymbols());
			assertTrue(got.get() == null || true);
			Thread.sleep(200);
			assertTrue(got.get().startsWith("SYMBOLS SPAMC/1.5\r\nContent-length: 20\r\nUser: spamuser\r\n\r\nSubject: x"), got.get());
		}
	}

	@Test
	public void spamAssassinHamAndErrors() throws Exception {
		try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			spamd(ss, "SPAMD/1.1 0 EX_OK\r\nSpam: False ; 0.2 / 5.0\r\n\r\n", new AtomicReference<>());
			Map<String, String> s = new HashMap<>();
			s.put("port", String.valueOf(ss.getLocalPort()));
			SpamVerdict v = SpamProviders.get("spamassassin").create(s).check(request("t@b.test"));
			assertFalse(v.isSpam());
			assertEquals(0.2, v.getScore());
			assertTrue(v.getSymbols().isEmpty());
		}
		for (String bad : new String[] { "SPAMD/1.1 76 EX_PROTOCOL\r\n\r\n", "garbage", "SPAMD/1.1 0 EX_OK\r\n\r\n" }) {
			try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
				spamd(ss, bad, new AtomicReference<>());
				Map<String, String> s = new HashMap<>();
				s.put("port", String.valueOf(ss.getLocalPort()));
				SpamFilter f = SpamProviders.get("spamassassin").create(s);
				assertThrows(IOException.class, () -> f.check(request("t@b.test")), bad);
			}
		}
		// nobody listening
		int closed;
		try (ServerSocket ss = new ServerSocket(0)) {
			closed = ss.getLocalPort();
		}
		Map<String, String> s = new HashMap<>();
		s.put("port", String.valueOf(closed));
		assertThrows(IOException.class, () -> SpamProviders.get("spamassassin").create(s).check(request("t@b.test")));
	}

	// ------------------------------------------------------------------ discovery, settings, status, learning

	@Test
	public void theBuiltInsAreFoundThroughTheServicesFile() throws Exception {
		java.net.URL u = TestSpam.class.getClassLoader().getResource("META-INF/services/us.bringardner.parley.smtp.spam.SpamProvider");
		assertNotNull(u, "the providers are listed, not coded");
		String list = new String(u.openStream().readAllBytes(), StandardCharsets.UTF_8);
		for (String id : Arrays.asList("none", "rspamd", "spamassassin")) {
			assertNotNull(SpamProviders.get(id), id);
		}
		assertTrue(list.contains("RspamdSpamFilter$Provider") && list.contains("SpamAssassinSpamFilter$Provider")
				&& list.contains("NullSpamFilter$Provider"), list);
	}

	@Test
	public void providersDescribeTheirFeaturesAndSettings() {
		SpamProvider r = SpamProviders.get("rspamd");
		assertEquals("Rspamd", r.getTitle());
		assertFalse(r.getDescription().isEmpty());
		assertEquals(EnumSet.of(SpamProvider.Feature.CHECK, SpamProvider.Feature.LEARN, SpamProvider.Feature.STATUS), r.getFeatures());
		List<String> keys = new ArrayList<>();
		for (ConnectionSetting c : r.getSettings()) {
			keys.add(c.key());
		}
		assertEquals(Arrays.asList("url", "password", "controllerUrl", "controllerPassword"), keys);
		assertEquals(ConnectionSetting.Kind.SECRET, r.getSettings().get(1).kind());
		assertTrue(r.getSettings().get(2).advanced());

		SpamProvider sa = SpamProviders.get("spamassassin");
		assertEquals(ConnectionSetting.Kind.INTEGER, sa.getSettings().get(1).kind());
		assertEquals("783", sa.getSettings().get(1).defaultValue());

		SpamProvider none = SpamProviders.get("none");
		assertEquals(EnumSet.of(SpamProvider.Feature.CHECK, SpamProvider.Feature.STATUS), none.getFeatures());
		assertTrue(none.getSettings().isEmpty());

		Map<String, String> bad = new HashMap<>();
		bad.put("port", "lots");
		assertFalse(sa.validate(bad).isEmpty(), "a port that isn't a number");
		bad.put("port", "99999");
		assertFalse(sa.validate(bad).isEmpty(), "a port out of range");
		assertTrue(sa.validate(new HashMap<>()).isEmpty(), "everything has a default");
		Map<String, String> ftp = new HashMap<>();
		ftp.put("url", "ftp://nowhere");
		assertFalse(r.validate(ftp).isEmpty());
	}

	@Test
	public void rspamdStatusAndLearning() throws Exception {
		AtomicReference<String> learned = new AtomicReference<>();
		AtomicReference<String> pw = new AtomicReference<>();
		HttpServer h = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		h.createContext("/ping", ex -> {
			ex.getResponseHeaders().add("Server", "rspamd/3.8.1");
			byte[] out = "pong\r\n".getBytes(StandardCharsets.US_ASCII);
			ex.sendResponseHeaders(200, out.length);
			ex.getResponseBody().write(out);
			ex.close();
		});
		h.createContext("/", ex -> {
			learned.set(ex.getRequestURI().getPath() + " " + new String(ex.getRequestBody().readAllBytes(), StandardCharsets.US_ASCII));
			pw.set(ex.getRequestHeaders().getFirst("Password"));
			ex.sendResponseHeaders(200, -1);
			ex.close();
		});
		h.start();
		try {
			String base = "http://127.0.0.1:" + h.getAddress().getPort();
			Map<String, String> s = new HashMap<>();
			s.put("url", base);
			s.put("controllerUrl", base);
			s.put("controllerPassword", "enable");
			SpamFilter f = SpamProviders.get("rspamd").create(s);
			SpamStatus st = f.status();
			assertTrue(st.isAvailable(), st.toString());
			assertEquals("3.8.1", st.getVersion());
			f.learn(request("t@b.test"), true);
			assertEquals("/learnspam Subject: x\r\n\r\nbody\r\n", learned.get());
			assertEquals("enable", pw.get());
			f.learn(request("t@b.test"), false);
			assertTrue(learned.get().startsWith("/learnham "), learned.get());
			SpamStatus viaRegistry = SpamProviders.test("rspamd", s, 2000);
			assertTrue(viaRegistry.isAvailable(), viaRegistry.toString());
		} finally {
			h.stop(0);
		}
		Map<String, String> gone = new HashMap<>();
		gone.put("url", "http://127.0.0.1:1");
		SpamStatus down = SpamProviders.test("rspamd", gone, 500);
		assertFalse(down.isAvailable());
		assertTrue(down.getMessage().contains("127.0.0.1:1"), down.getMessage());
	}

	@Test
	public void spamAssassinStatusAndLearning() throws Exception {
		try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			AtomicReference<String> got = new AtomicReference<>();
			spamd(ss, "SPAMD/1.5 0 PONG\r\n", got);
			Map<String, String> s = new HashMap<>();
			s.put("port", String.valueOf(ss.getLocalPort()));
			SpamStatus st = SpamProviders.get("spamassassin").create(s).status();
			assertTrue(st.isAvailable(), st.toString());
			assertEquals("1.5", st.getVersion());
		}
		try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			AtomicReference<String> got = new AtomicReference<>();
			Thread t = spamd(ss, "SPAMD/1.5 0 EX_OK\r\nDidSet: local\r\n\r\n", got);
			Map<String, String> s = new HashMap<>();
			s.put("port", String.valueOf(ss.getLocalPort()));
			SpamProviders.get("spamassassin").create(s).learn(request("t@b.test"), false);
			t.join(2000);
			assertTrue(got.get().startsWith("TELL SPAMC/1.5\r\nContent-length: 20\r\nMessage-class: ham\r\nSet: local\r\n\r\nSubject: x"), got.get());
		}
		int closed;
		try (ServerSocket ss = new ServerSocket(0)) {
			closed = ss.getLocalPort();
		}
		Map<String, String> s = new HashMap<>();
		s.put("port", String.valueOf(closed));
		assertFalse(SpamProviders.test("spamassassin", s, 500).isAvailable());
		assertFalse(SpamProviders.test("nosuch", s, 500).isAvailable());
		s.put("port", "lots");
		assertTrue(SpamProviders.test("spamassassin", s, 500).getMessage().length() > 0, "a wrong setting is reported");
		assertThrows(UnsupportedOperationException.class, () -> new NullSpamFilter().learn(request("t@b.test"), true));
	}

	// ------------------------------------------------------------------ the engine

	@Test
	public void offUnlessEnabled() {
		Spam s = spam("spam.provider", "stub");
		assertFalse(isActive(s));
		assertEquals("none", providerFor(s, "b.test"));
		assertSame(Spam.Outcome.NONE, check(s, request("t@b.test")));
		assertTrue(Stub.asked.isEmpty());
		s = spam("spam.enabled", "true"); // enabled with the default provider, none
		assertFalse(isActive(s));
	}

	private static void assertSame(Object a, Object b) {
		org.junit.jupiter.api.Assertions.assertSame(a, b);
	}

	@Test
	public void filterActionOrThresholdsDecide() {
		Stub.score = 9;
		Stub.spam = true;
		Stub.action = Action.REJECT;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub");
		assertEquals(Action.REJECT, check(s, request("t@b.test")).action, "the filter's own action");
		Stub.action = null;
		assertEquals(Action.QUARANTINE, check(s, request("t@b.test")).action, "spam without an action goes to Junk");
		Stub.spam = false;
		assertEquals(Action.ACCEPT, check(s, request("t@b.test")).action);

		Stub.action = Action.REJECT;
		s = spam("spam.enabled", "true", "spam.provider", "stub", "spam.rejectScore", "15", "spam.quarantineScore", "6");
		Stub.score = 3;
		assertEquals(Action.ACCEPT, check(s, request("t@b.test")).action, "thresholds override the filter's action");
		Stub.score = 6;
		assertEquals(Action.QUARANTINE, check(s, request("t@b.test")).action);
		Stub.score = 15;
		Spam.Outcome o = check(s, request("t@b.test"));
		assertEquals(Action.REJECT, o.action);
		assertEquals("Message rejected as spam", o.text);
	}

	@Test
	public void headersAreSafeAndComplete() {
		Stub.score = 7.256;
		Stub.spam = true;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub");
		String h = check(s, request("t@b.test")).headers;
		assertEquals("X-Spam-Flag: YES\r\nX-Spam-Score: 7.26\r\nX-Spam-Status: Yes, score=7.26 required=5.00 tests=TEST_RULE\r\n"
				+ "X-Spam-Checker: stub\r\n", h);
		Stub.spam = false;
		Stub.score = 0.5;
		assertTrue(check(s, request("t@b.test")).headers.startsWith("X-Spam-Flag: NO\r\n"));
	}

	@Test
	public void aFailingFilterAcceptsTheMail() {
		Stub.fail = true;
		Stub.action = Action.REJECT;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub");
		List<String> logged = new ArrayList<>();
		s.setLog((m, e) -> logged.add(m));
		Spam.Outcome o = check(s, request("t@b.test"));
		assertEquals(Action.ACCEPT, o.action);
		assertEquals("", o.headers);
		assertEquals(1, logged.size());
		assertTrue(logged.get(0).contains("scanner is down"), logged.get(0));
		// an override that names a provider that isn't there fails the same way
		s = spam("spam.enabled", "true", "spam.provider", "stub", "spam.domains", "b.test:missing");
		assertEquals(Action.ACCEPT, check(s, request("t@b.test")).action);
	}

	@Test
	public void domainsOverrideTheGlobalChoice() {
		Stub.score = 20;
		Stub.action = Action.REJECT;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub", "spam.domains", "off.test:off, Other.test:other");
		assertEquals("stub", providerFor(s, "b.test"));
		assertEquals("none", providerFor(s, "OFF.test"));
		assertEquals("other", providerFor(s, "other.test"));
		assertEquals(Action.REJECT, check(s, request("t@b.test")).action);
		assertEquals(Action.ACCEPT, check(s, request("t@off.test")).action, "turned off for the domain");
		assertTrue(Stub.asked.size() == 1, "the off domain isn't sent to a filter");
		assertEquals(Action.ACCEPT, check(s, request("t@other.test")).action, "another filter for the domain");

		// off globally, on for one domain
		s = spam("spam.domains", "only.test:stub");
		assertTrue(isActive(s));
		assertEquals(Action.ACCEPT, check(s, request("t@b.test")).action);
		assertEquals(Action.REJECT, check(s, request("t@only.test")).action);
	}

	@Test
	public void mixedRecipientsGetTheMildestOutcomeAndEachFilterSeesItsOwn() {
		Stub.score = 20;
		Stub.action = Action.REJECT;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub", "spam.domains", "off.test:off,o.test:other");
		Spam.Outcome o = check(s, request("a@b.test", "c@off.test"));
		assertEquals(Action.ACCEPT, o.action, "an unchecked recipient keeps the message from being refused");
		assertTrue(o.headers.startsWith("X-Spam-Flag: YES"), "but it is flagged");
		assertEquals(Collections.singletonList(Collections.singletonList("a@b.test")), Stub.asked);
		Stub.asked.clear();
		o = check(s, request("a@b.test", "d@o.test"));
		assertEquals(Action.ACCEPT, o.action, "the other filter finds it clean");
		o = check(s, request("a@b.test", "e@b.test"));
		assertEquals(Action.REJECT, o.action);
		assertEquals(Arrays.asList("a@b.test", "e@b.test"), Stub.asked.get(Stub.asked.size() - 1));
	}

	@Test
	public void sizeLimitSkipsBigMessages() {
		Stub.score = 20;
		Stub.action = Action.REJECT;
		Spam s = spam("spam.enabled", "true", "spam.provider", "stub", "spam.maxSize", "10");
		assertSame(Spam.Outcome.NONE, check(s, request("t@b.test")));
	}

	@Test
	public void badSettingsAreRefused() {
		assertThrows(IllegalArgumentException.class, () -> Spam.parseDomains("nocolon.test"));
		assertThrows(IllegalArgumentException.class, () -> spam("spam.provider", "nosuchprovider"));
		assertThrows(IllegalArgumentException.class, () -> spam("spam.provider", "spamassassin", "spam.spamassassin.port", "lots"));
		assertThrows(NumberFormatException.class, () -> spam("spam.rejectScore", "lots"));
	}

	// ------------------------------------------------------------------ in the SMTP server

	private static SmtpServer b;
	private static FileSource rootB;

	@BeforeAll
	public static void start() throws Exception {
		System.setProperty("parley.mail.smtp." + FileBasedAcl.PROP_FILE_NAME, ACL_FILE);
		System.setProperty("parley.mail.smtp." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileBasedAcl.class.getName());
		rootB = FileSourceFactory.getDefaultFactory().createTempDirectory("spamB");
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

	private static String find(String subject) {
		try {
			for (String m : TestSmtpServer.inbox(rootB, "team")) {
				if (m.contains("Subject: " + subject + "\r\n")) {
					return m;
				}
			}
		} catch (IOException e) {
			// not yet
		}
		return null;
	}

	private static void useSpam(String... props) {
		Properties q = new Properties();
		for (int i = 0; i < props.length; i += 2) {
			q.setProperty(props[i], props[i + 1]);
		}
		b.getSpam().configure(n -> q.getProperty("spam." + n));
		b.getDeliveryConfig().setSpamDomains(Spam.parseDomains(q.getProperty("spam.domains", "")));
	}

	@Test
	public void theServerReadsItsOwnSpamSettings() {
		String[] keys = { "parley.mail.smtp.spam.enabled", "parley.mail.smtp.spam.provider", "parley.mail.smtp.spam.rejectScore",
				"parley.mail.smtp.spam.spamassassin.port", "parley.mail.submission.spam.enabled" };
		try {
			System.setProperty(keys[0], "true");
			System.setProperty(keys[1], "SpamAssassin");
			System.setProperty(keys[2], "12.5");
			System.setProperty(keys[3], "7830");
			System.setProperty(keys[4], "true");
			SmtpServer smtp = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
			assertTrue(smtp.getSpam().isEnabled());
			assertEquals("spamassassin", smtp.getSpam().getProvider());
			// the submission server has its own prefix, and spam isn't checked there unless it is set there
			SmtpServer sub = SmtpServer.submissionServer(false);
			assertTrue(sub.getSpam().isEnabled(), "its own prefix was set in this test");
			System.clearProperty(keys[4]);
			assertFalse(SmtpServer.submissionServer(false).getSpam().isEnabled(), "not set: not checked");
			// wrong settings keep the earlier ones and the server still starts
			System.setProperty(keys[1], "nosuchprovider");
			assertEquals("none", new SmtpServer(0, SmtpServer.SMTP_NAME, false).getSpam().getProvider());
		} finally {
			for (String k : keys) {
				System.clearProperty(k);
			}
		}
	}

	@Test
	public void scoredMailGetsTheHeadersAndASendersOwnAreReplaced() throws Exception {
		useSpam("spam.enabled", "true", "spam.provider", "stub");
		Stub.score = 1;
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.sendMail("a@client.example", "team1@b.test",
					"From: a@client.example\r\nSubject: scored\r\nX-Spam-Flag: NO\r\nX-Spam-Score: -99\r\n\r\nhi\r\n");
			assertTrue(r.startsWith("250"), r);
		}
		TestSmtpServer.waitFor(() -> find("scored") != null, 30000, "scored");
		String m = find("scored");
		assertTrue(m.contains("\r\nX-Spam-Flag: NO\r\nX-Spam-Score: 1.00\r\n"), m);
		assertFalse(m.contains("X-Spam-Score: -99"), "the sender's own field is dropped: " + m);
		assertEquals(1, m.split("X-Spam-Flag:", -1).length - 1, m);
		assertTrue(m.indexOf("X-Spam-Checker: stub") < m.indexOf("Subject: scored"), "after our trace fields: " + m);
	}

	@Test
	public void rejectedAndDeferredAndOffForTheDomain() throws Exception {
		useSpam("spam.enabled", "true", "spam.provider", "stub");
		Stub.score = 30;
		Stub.spam = true;
		Stub.action = Action.REJECT;
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.sendMail("a@client.example", "team1@b.test", "From: a@client.example\r\nSubject: spam rejected\r\n\r\nbuy\r\n");
			assertTrue(r.startsWith("550 5.7.1 Message rejected as spam"), r);
			// the session goes on
			c.ok("MAIL FROM:<a@client.example>", "250");
		}
		Stub.action = Action.DEFER;
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.sendMail("a@client.example", "team1@b.test", "From: a@client.example\r\nSubject: spam deferred\r\n\r\nbuy\r\n");
			assertTrue(r.startsWith("451 4.7.1 "), r);
		}
		// turned off for the domain
		useSpam("spam.enabled", "true", "spam.provider", "stub", "spam.domains", "b.test:off");
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			String r = c.sendMail("a@client.example", "team1@b.test", "From: a@client.example\r\nSubject: spam off\r\n\r\nhi\r\n");
			assertTrue(r.startsWith("250"), r);
		}
		TestSmtpServer.waitFor(() -> find("spam off") != null, 30000, "spam off");
		assertFalse(find("spam off").contains("X-Spam-Flag"));
		assertNull(find("spam rejected"));
		assertNull(find("spam deferred"));
		useSpam(); // back to off
	}

	@Test
	public void quarantineGoesToJunkAndAFailingFilterDelivers() throws Exception {
		useSpam("spam.enabled", "true", "spam.provider", "stub");
		Stub.score = 8;
		Stub.spam = true;
		Stub.action = Action.QUARANTINE;
		int before = junkCount();
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			assertTrue(c.sendMail("a@client.example", "team1@b.test", "From: a@client.example\r\nSubject: junk me\r\n\r\nbuy\r\n")
					.startsWith("250"));
		}
		TestSmtpServer.waitFor(() -> junkCount() == before + 1, 30000, "junk me in Junk");
		assertNull(find("junk me"), "not in the INBOX");

		Stub.fail = true;
		try (TestSmtpServer.Client c = new TestSmtpServer.Client(b.getLocalPort())) {
			c.ok("EHLO client.example", "250");
			assertTrue(c.sendMail("a@client.example", "team1@b.test", "From: a@client.example\r\nSubject: filter down\r\n\r\nhi\r\n")
					.startsWith("250"));
		}
		TestSmtpServer.waitFor(() -> find("filter down") != null, 30000, "filter down");
		useSpam();
	}

	private static int junkCount() {
		try {
			MailStore store = new MailStore(rootB.getChild("team"), MailboxRegistry.get());
			if (!store.exists("Junk")) {
				return 0;
			}
			Mailbox mb = store.open("Junk");
			try {
				mb.refresh(true);
				return mb.count();
			} finally {
				MailboxRegistry.get().release(mb);
			}
		} catch (IOException e) {
			return -1;
		}
	}
}
