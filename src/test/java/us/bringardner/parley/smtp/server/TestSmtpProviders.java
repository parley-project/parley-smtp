package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.server.LaunchSettings;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerLauncher;
import us.bringardner.parley.smtp.queue.MailQueueMXBean;
import us.bringardner.parley.smtp.queue.QueueHistory;

/**
 * The SMTP providers: the relay and submission servers sharing one queue (made when the first
 * starts, let go when the last stops), the queue's JMX bean, and its history.
 */
public class TestSmtpProviders {

	private static final String[] CLEARED = { "parley.mail.smtp.port", "parley.mail.submission.port", "parley.mail.submissions.port",
			"parley.mail.smtp.secure", "parley.mail.users", "parley.mail.root", "parley.mail.smtp.domains", "parley.mail.smtp.hostname",
			"parley.mail.smtp.authenticationProvider", "parley.mail.smtp.userFile", "parley.mail.submission.authenticationProvider",
			"parley.mail.submission.userFile", QueueHistory.HISTORY_PROP, QueueHistory.DIRECTORY_PROP };

	@TempDir
	File dir;

	private final Map<String, String> saved = new HashMap<>();
	private ServerLauncher launcher;

	@BeforeEach
	public void clear() {
		for (String n : CLEARED) {
			saved.put(n, System.getProperty(n));
			System.clearProperty(n);
		}
	}

	@AfterEach
	public void restore() {
		if (launcher != null) {
			launcher.close();
		}
		for (String n : CLEARED) {
			System.clearProperty(n);
			if (saved.get(n) != null) {
				System.setProperty(n, saved.get(n));
			}
		}
	}

	private static int freePort() throws Exception {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}

	private void write(String name, String... lines) throws Exception {
		// (a .properties file reads \ as an escape: the paths in it have / on Windows)
		Files.write(new File(dir, name).toPath(), (String.join("\n", lines).replace('\\', '/') + "\n").getBytes(StandardCharsets.UTF_8));
	}

	private static String reply(BufferedReader in) throws IOException {
		String line;
		do {
			line = in.readLine();
		} while (line != null && line.length() > 3 && line.charAt(3) == '-');
		return line;
	}

	private static void send(int port) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			String[][] dialog = { { "EHLO client.example", "250" }, { "MAIL FROM:<someone@example.com>", "250" },
					{ "RCPT TO:<tony@localhost>", "250" }, { "DATA", "354" },
					{ "Subject: hi\r\nFrom: someone@example.com\r\nTo: tony@localhost\r\n\r\nHello\r\n.", "250" }, { "QUIT", "221" } };
			for (String[] step : dialog) {
				out.write((step[0] + "\r\n").getBytes(StandardCharsets.US_ASCII));
				String r = reply(in);
				assertTrue(r != null && r.startsWith(step[1]), step[0] + ": " + r);
			}
		}
	}

	@Test
	public void providersFound() {
		assertTrue(ServerLauncher.providers().keySet().containsAll(Arrays.asList("smtp", "submission", "submissions")));
	}

	@Test
	public void relayAndSubmissionShareTheQueue() throws Exception {
		int smtp = freePort();
		int submission = freePort();
		File mail = new File(dir, "mail");
		write("users.txt", "tony , secret , READ|WRITE");
		write("parley-mail.properties", "parley.mail.root=" + mail.getPath(), "parley.mail.users=" + new File(dir, "users.txt").getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + smtp, "parley.mail.submission.port=" + submission,
				"parley.mail.smtp.hostname=localhost", "parley.mail.smtp.domains=localhost");
		ServerContext context = new ServerContext();
		launcher = new ServerLauncher("SmtpTest", new LaunchSettings(new Properties()), Arrays.asList("smtp", "submission", "submissions"), dir,
				context);
		launcher.init();
		assertEquals(ServerLauncher.State.OFF, launcher.getState("submissions"));
		launcher.startAll();
		assertEquals(ServerLauncher.State.RUNNING, launcher.getState("smtp"));
		assertEquals(ServerLauncher.State.RUNNING, launcher.getState("submission"));

		SmtpProviders.SharedQueue shared = (SmtpProviders.SharedQueue) context.get(SmtpProviders.SHARED_QUEUE);
		assertNotNull(shared.getQueue());
		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		ObjectName name = new ObjectName("us.bringardner.parley:type=MailQueue,name=smtp");
		assertTrue(mbs.isRegistered(name));
		MailQueueMXBean q = JMX.newMXBeanProxy(mbs, name, MailQueueMXBean.class);
		assertTrue(q.isRunning());
		assertEquals(new File(mail, QueueHistory.DEFAULT_DIRECTORY).getAbsolutePath(), q.getHistoryDirectory());

		send(smtp);
		File history = new File(q.getHistoryDirectory(), QueueHistory.PREFIX + LocalDate.now() + QueueHistory.SUFFIX);
		String text = "";
		for (int i = 0; i < 100 && !text.contains("\"DELIVERED\""); i++) {
			Thread.sleep(100);
			text = history.isFile() ? new String(Files.readAllBytes(history.toPath()), StandardCharsets.UTF_8) : "";
		}
		assertTrue(text.contains("\"type\":\"QUEUED\"") && text.contains("\"recipient\":\"tony@localhost\""), text);
		assertTrue(text.contains("\"type\":\"DELIVERED\""), text);

		// the open connections, through the queue-sharing wrapper
		try (Socket open = new Socket("127.0.0.1", submission)) {
			new BufferedReader(new InputStreamReader(open.getInputStream(), StandardCharsets.US_ASCII)).readLine(); // the greeting
			us.bringardner.parley.net.server.ParleyConnection[] list = launcher.getServer("submission").getConnectionList();
			assertEquals(1, list.length);
			assertTrue(list[0].getRemote().startsWith("127.0.0.1:"), list[0].getRemote());
			assertEquals(null, list[0].getUser(), "not logged in");
			assertFalse(list[0].isSecure());
		}

		// restarting one SMTP server keeps the queue; stopping both lets it go
		java.lang.Object before = shared.getQueue();
		launcher.restart("submission");
		assertSame(before, shared.getQueue());
		launcher.stop("smtp");
		launcher.stop("submission");
		assertEquals(null, shared.getQueue());
		assertFalse(mbs.isRegistered(name));
		launcher.start("smtp");
		assertTrue(mbs.isRegistered(name), "a new queue when an SMTP server starts again");
	}

	/** AUTH PLAIN on a server; the reply's code */
	private static String auth(int port, String user, String password) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			s.setSoTimeout(20000);
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			out.write("EHLO client.example\r\n".getBytes(StandardCharsets.US_ASCII));
			assertTrue(reply(in).startsWith("250"));
			String token = java.util.Base64.getEncoder().encodeToString(("\0" + user + "\0" + password).getBytes(StandardCharsets.UTF_8));
			out.write(("AUTH PLAIN " + token + "\r\n").getBytes(StandardCharsets.US_ASCII));
			String r = reply(in);
			return r.substring(0, 3);
		}
	}

	@Test
	public void aSubmissionServerWithItsOwnUsersKeepsThem() throws Exception {
		int smtp = freePort();
		int submission = freePort();
		write("users.txt", "tony , secret , READ|WRITE");
		write("own.txt", "jose , other , READ|WRITE");
		write("parley-mail.properties", "parley.mail.root=" + new File(dir, "mail").getPath(), "parley.mail.users=" + new File(dir, "users.txt").getPath());
		write("parley-smtp.properties", "parley.mail.smtp.port=" + smtp, "parley.mail.submission.port=" + submission,
				"parley.mail.smtp.hostname=localhost", "parley.mail.smtp.domains=localhost",
				"parley.mail.submission.authenticationProvider=us.bringardner.parley.net.server.FileBasedAcl",
				"parley.mail.submission.userFile=" + new File(dir, "own.txt").getPath());
		ServerContext context = new ServerContext(javax.management.MBeanServerFactory.newMBeanServer());
		launcher = new ServerLauncher("SmtpUsersTest", new LaunchSettings(new Properties()), Arrays.asList("smtp", "submission"), dir, context);
		launcher.init();
		launcher.startAll();
		assertEquals("235", auth(submission, "jose", "other"), "its own users");
		assertEquals("535", auth(submission, "tony", "secret"), "not the shared users");
		assertEquals("235", auth(smtp, "tony", "secret"), "the relay has the shared users");
		assertNotNull(us.bringardner.parley.mail.server.AbstractMailServer.sharedUsers(context, new File(dir, "users.txt")));
	}

	@Test
	public void legacySecureRelay() {
		System.setProperty("parley.mail.smtp.secure", "true");
		System.setProperty("parley.mail.smtps.port", "0");
		try {
			assertFalse(ServerLauncher.providers().get("smtp").enabled(), "the relay's port is parley.mail.smtps.port then");
		} finally {
			System.clearProperty("parley.mail.smtps.port");
		}
	}
}
