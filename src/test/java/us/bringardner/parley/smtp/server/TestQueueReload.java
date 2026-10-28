package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.server.LaunchSettings;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerLauncher;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.queue.MailQueue;
import us.bringardner.parley.smtp.queue.MailQueueMXBean;
import us.bringardner.parley.smtp.test.MailStoreSetup;

/**
 * The queue's reload over JMX: a domain, its aliases and its DKIM key added to the queue's settings
 * are used at once by a running server, with no restart; settings that can't be read change nothing;
 * a domain taken out is no longer local.
 */
public class TestQueueReload {

	private static final String[] CLEARED = { "parley.mail.smtp.port", "parley.mail.submission.port", "parley.mail.submissions.port",
			"parley.mail.users", "parley.mail.root", "parley.mail.smtp.hostname" };

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

	private void write(File f, String... lines) throws Exception {
		Files.write(f.toPath(), (String.join("\n", lines).replace('\\', '/') + "\n").getBytes(StandardCharsets.UTF_8));
	}

	private static FileSource fs(File f) throws IOException {
		return FileSourceFactory.getDefaultFactory().createFileSource(f.getPath());
	}

	private static String reply(BufferedReader in) throws IOException {
		String line;
		do {
			line = in.readLine();
		} while (line != null && line.length() > 3 && line.charAt(3) == '-');
		return line;
	}

	/** The server's answer to RCPT TO for this address (from a client it doesn't relay for) */
	private static String rcpt(int port, String address) throws Exception {
		try (Socket s = new Socket("127.0.0.1", port)) {
			BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
			OutputStream out = s.getOutputStream();
			assertTrue(reply(in).startsWith("220"));
			out.write("EHLO client.example\r\n".getBytes(StandardCharsets.US_ASCII));
			assertTrue(reply(in).startsWith("250"));
			out.write("MAIL FROM:<someone@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));
			assertTrue(reply(in).startsWith("250"));
			out.write(("RCPT TO:<" + address + ">\r\n").getBytes(StandardCharsets.US_ASCII));
			String r = reply(in);
			out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
			return r;
		}
	}

	private void queueSettings(File queueDir, String domains, String... more) throws Exception {
		Properties q = MailQueue.readSettings(fs(queueDir));
		q.setProperty("domains", domains);
		for (int i = 0; i + 1 < more.length; i += 2) {
			if (more[i + 1] == null) {
				q.remove(more[i]);
			} else {
				q.setProperty(more[i], more[i + 1]);
			}
		}
		MailQueue.writeSettings(fs(queueDir), q);
	}

	@Test
	public void aNewDomainItsAliasesAndKeyAreUsedWithoutARestart() throws Exception {
		int port = freePort();
		File mail = new File(dir, "mail");
		MailStoreSetup.setUp(fs(mail), "mx.localhost", "localhost");
		File users = new File(dir, "users.txt");
		write(users, "tony , secret , READ|WRITE");
		write(new File(dir, "parley-mail.properties"), "parley.mail.root=" + mail.getPath(), "parley.mail.users=" + users.getPath());
		write(new File(dir, "parley-smtp.properties"), "parley.mail.smtp.port=" + port, "parley.mail.submission.port=0",
				"parley.mail.smtp.hostname=mx.localhost");
		MBeanServer mbs = MBeanServerFactory.newMBeanServer();
		launcher = new ServerLauncher("SmtpReload", new LaunchSettings(new Properties()), Arrays.asList("smtp"), dir, new ServerContext(mbs));
		launcher.init();
		launcher.startAll();
		File queueDir = new File(mail, SmtpServer.QUEUE_DIRECTORY);
		MailQueueMXBean bean = JMX.newMXBeanProxy(mbs, new ObjectName("us.bringardner.parley:type=MailQueue,name=smtp"), MailQueueMXBean.class);

		assertTrue(rcpt(port, "tony@localhost").startsWith("250"));
		assertTrue(rcpt(port, "boss@new.example").startsWith("5"), "not a local domain yet");

		// the administrator adds the domain, an alias and a DKIM key
		File aliases = new File(dir, "aliases");
		write(aliases, "# aliases", "boss@new.example: tony");
		File key = new File(dir, "new.example.pem");
		Files.write(key.toPath(), DkimKeys.toPem(DkimKeys.generate("rsa").getPrivate()).getBytes(StandardCharsets.US_ASCII));
		queueSettings(queueDir, "localhost, new.example", "aliases", aliases.getPath(), "dkim.keys", "new.example:s1:" + key.getPath());
		assertTrue(rcpt(port, "boss@new.example").startsWith("5"), "not before the reload");

		String used = bean.reload();
		assertTrue(used.contains("domains [localhost, new.example]") && used.contains("1 aliases") && used.contains("DKIM keys for [new.example]"), used);
		assertTrue(rcpt(port, "boss@new.example").startsWith("250"), "the alias of the new domain");
		assertTrue(rcpt(port, "tony@localhost").startsWith("250"), "the other domain still");

		// settings that can't be read: an error, and nothing changes
		queueSettings(queueDir, "localhost", "aliases", new File(dir, "missing").getPath());
		IOException e = assertThrows(IOException.class, () -> bean.reload());
		assertTrue(e.getMessage().contains("aliases"), e.getMessage());
		assertTrue(rcpt(port, "boss@new.example").startsWith("250"), "the domain read before is still used");
		queueSettings(queueDir, "localhost", "aliases", aliases.getPath(), "dkim.keys", "new.example:s1:" + new File(dir, "nokey.pem").getPath());
		e = assertThrows(IOException.class, () -> bean.reload());
		assertTrue(e.getMessage().contains("DKIM"), e.getMessage());
		assertTrue(rcpt(port, "boss@new.example").startsWith("250"), "the aliases read before are still used");

		// a shared key: named in the reload's answer; one whose domain has no key is refused
		queueSettings(queueDir, "localhost, new.example", "aliases", aliases.getPath(), "dkim.keys", "new.example:s1:" + key.getPath(),
				"dkim.shared", "new.example");
		used = bean.reload();
		assertTrue(used.contains("shared key new.example"), used);
		queueSettings(queueDir, "localhost, new.example", "dkim.shared", "localhost");
		e = assertThrows(IOException.class, () -> bean.reload());
		assertTrue(e.getMessage().contains("shared DKIM key"), e.getMessage());

		// the domain and its key taken out
		queueSettings(queueDir, "localhost", "dkim.keys", null, "dkim.shared", null);
		used = bean.reload();
		assertTrue(used.contains("domains [localhost]") && used.contains("DKIM keys for []"), used);
		assertTrue(rcpt(port, "boss@new.example").startsWith("5"), "no longer a local domain");
		assertTrue(rcpt(port, "tony@localhost").startsWith("250"));
	}
}
