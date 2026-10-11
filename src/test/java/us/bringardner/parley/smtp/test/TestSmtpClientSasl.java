package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.sasl.ISaslAuthenticator;
import us.bringardner.parley.net.sasl.ISaslChannel;
import us.bringardner.parley.net.sasl.ISaslClient;
import us.bringardner.parley.net.sasl.ISaslMechanism;
import us.bringardner.parley.net.sasl.ISaslServer;
import us.bringardner.parley.net.sasl.PlainMechanism;
import us.bringardner.parley.net.sasl.SaslEncoding;
import us.bringardner.parley.net.sasl.SaslOutcome;
import us.bringardner.parley.net.sasl.SaslServerDriver;
import us.bringardner.parley.net.sasl.SaslStep;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.sasl.ScramMechanism;
import us.bringardner.parley.smtp.queue.SmtpClient;

/**
 * The client's SASL login against a scripted server that runs the real SCRAM server side.
 */
public class TestSmtpClientSasl {

	private static final String USER = "alice";
	private static final String PASSWORD = "s3cret";

	private ServerSocket listener;
	private final List<String> mechanisms = new CopyOnWriteArrayList<>();

	@AfterEach
	public void stop() throws IOException {
		if (listener != null) {
			listener.close();
		}
	}

	private static ISaslAuthenticator users() {
		final ScramCredentials stored = ScramMechanism.SHA_256.deriveCredentials(PASSWORD,
				"0123456789abcdef".getBytes(StandardCharsets.US_ASCII), 4096);
		return new ISaslAuthenticator() {
			@Override
			public boolean checkPassword(String user, String password) {
				return USER.equals(user) && PASSWORD.equals(password);
			}

			@Override
			public ScramCredentials getScramCredentials(String user, String hash) {
				return USER.equals(user) && "SHA-256".equals(hash) ? stored : null;
			}
		};
	}

	private int serve(boolean honest) throws IOException {
		listener = new ServerSocket(0);
		Thread t = new Thread(() -> {
			try (Socket s = listener.accept()) {
				session(s, honest);
			} catch (IOException e) {
				// the test closed the listener or the client went away
			}
		});
		t.setDaemon(true);
		t.start();
		return listener.getLocalPort();
	}

	private void session(Socket s, boolean honest) throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
		Writer out = new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8);
		out.write("220 test.example ESMTP\r\n");
		out.flush();
		ISaslAuthenticator users = users();
		String line;
		while ((line = in.readLine()) != null) {
			String[] w = line.split(" ", 3);
			String cmd = w[0].toUpperCase();
			if (cmd.equals("EHLO")) {
				out.write("250-test.example hello\r\n250-8BITMIME\r\n250-AUTH SCRAM-SHA-256 PLAIN\r\n250 SIZE 1000\r\n");
			} else if (cmd.equals("AUTH")) {
				String mech = w[1].toUpperCase();
				String ir = w.length > 2 ? w[2] : null;
				mechanisms.add(mech);
				boolean ok;
				if (mech.equals("SCRAM-SHA-256") && !honest) {
					ok = dishonestScram(users, ir, in, out);
				} else {
					ISaslMechanism m = mech.equals("PLAIN") ? new PlainMechanism() : ScramMechanism.SHA_256;
					SaslOutcome o = SaslServerDriver.authenticate(m, users, ir, new ISaslChannel() {
						@Override
						public void sendChallenge(String base64) throws IOException {
							out.write("334 " + base64 + "\r\n");
							out.flush();
						}

						@Override
						public String readResponse() throws IOException {
							return in.readLine();
						}
					});
					ok = o.isSuccess();
				}
				out.write(ok ? "235 2.7.0 Authentication successful\r\n" : "535 5.7.8 Authentication failed\r\n");
			} else if (cmd.equals("QUIT")) {
				out.write("221 bye\r\n");
				out.flush();
				return;
			} else {
				out.write("250 ok\r\n");
			}
			out.flush();
		}
	}

	private static boolean dishonestScram(ISaslAuthenticator users, String ir, BufferedReader in, Writer out)
			throws IOException {
		ISaslServer server = ScramMechanism.SHA_256.newServer(users);
		SaslStep first = server.start(SaslEncoding.decode(ir));
		if (first.getKind() != SaslStep.Kind.CHALLENGE) {
			return false;
		}
		out.write("334 " + SaslEncoding.encode(first.getData()) + "\r\n");
		out.flush();
		in.readLine(); // the client's proof, accepted without a look
		return true;
	}

	private SmtpClient connect(int port) throws IOException {
		SmtpClient c = new SmtpClient("localhost", port, 5000, 10000);
		assertEquals(220, c.readReply().code);
		assertEquals(250, c.hello("client.example").code);
		return c;
	}

	@Test
	public void capabilitiesComeFromEhlo() throws Exception {
		int port = serve(true);
		SmtpClient c = connect(port);
		assertTrue(c.getCapabilities().has("AUTH", "SCRAM-SHA-256"));
		assertTrue(c.getCapabilities().has("auth", "plain"));
		assertEquals(Arrays.asList("1000"), c.getCapabilities().getParams("SIZE"));
		assertTrue(c.getCapabilities().has("8BITMIME"));
		assertFalse(c.getCapabilities().has("hello"), "the greeting line is not an extension");
		assertTrue(c.supports("SIZE"), "the older map is still filled");
	}

	@Test
	public void scramLoginNeverSendsThePassword() throws Exception {
		int port = serve(true);
		SmtpClient c = connect(port);
		ISaslClient sasl = c.chooseSasl(USER, PASSWORD, Arrays.asList("SCRAM-SHA-256", "PLAIN"));
		assertNotNull(sasl);
		assertEquals(235, c.authenticate(sasl).code);
		assertEquals(Collections.singletonList("SCRAM-SHA-256"), mechanisms);
	}

	@Test
	public void aWrongPasswordIsRefused() throws Exception {
		int port = serve(true);
		SmtpClient c = connect(port);
		ISaslClient sasl = c.chooseSasl(USER, "wrong", Arrays.asList("SCRAM-SHA-256", "PLAIN"));
		assertEquals(535, c.authenticate(sasl).code);
		assertEquals(Collections.singletonList("SCRAM-SHA-256"), mechanisms);
	}

	@Test
	public void aServerThatSkipsItsProofIsRefused() throws Exception {
		int port = serve(false);
		SmtpClient c = connect(port);
		ISaslClient sasl = c.chooseSasl(USER, PASSWORD, Arrays.asList("SCRAM-SHA-256"));
		IOException e = assertThrows(IOException.class, () -> c.authenticate(sasl));
		assertTrue(e.getMessage().contains("SCRAM-SHA-256"), e.getMessage());
	}

	@Test
	public void plainWorksThroughTheSameCall() throws Exception {
		int port = serve(true);
		SmtpClient c = connect(port);
		ISaslClient sasl = c.chooseSasl(USER, PASSWORD, Arrays.asList("PLAIN", "SCRAM-SHA-256"));
		assertEquals(235, c.authenticate(sasl).code);
		assertEquals(Collections.singletonList("PLAIN"), mechanisms);
	}

	@Test
	public void noMatchGivesNull() throws Exception {
		int port = serve(true);
		SmtpClient c = connect(port);
		assertNull(c.chooseSasl(USER, PASSWORD, Arrays.asList("CRAM-MD5", "SCRAM-SHA-1")));
		assertNull(c.chooseSasl(USER, PASSWORD, Collections.<String>emptyList()));
	}
}
