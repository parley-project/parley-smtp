package us.bringardner.parley.smtp.server;

import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.management.JMException;
import javax.management.ObjectName;

import us.bringardner.parley.mail.server.AbstractMailServer;
import us.bringardner.parley.mail.server.MailServerProvider;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.smtp.SMTP;
import us.bringardner.parley.smtp.queue.MailQueueBean;

/**
 * The SMTP servers a launcher can run ({@code parley.servers=smtp,submission,submissions}): the
 * relay (MX, port 25), submission (587) and submission with implicit TLS (465). Each is made from
 * its own configuration, read from {@code parley-mail.properties}, then {@code parley-smtp.properties}
 * (or the file {@code parley.mail.smtp.configFile} names).
 * <p>
 * Each server opens the queue its settings name ({@code <prefix>.queue}, default
 * {@code .smtp-queue} under the maildrop root); servers given the same queue share it through the
 * store's locks, as servers in separate processes would. While a server runs its queue is the JMX
 * bean {@code us.bringardner.parley:type=MailQueue,name=ID} (the server's id: smtp, submission, ...;
 * {@link us.bringardner.parley.smtp.queue.MailQueueMXBean}).
 *
 * @since 2.0.0
 */
public final class SmtpProviders {

	private SmtpProviders() {
	}

	/** A server whose queue is a JMX bean while it runs */
	static ServerMain.Service service(SmtpServer server, String id, String name, ServerContext context) {
		ServerMain.Service s = ServerMain.service(server, name);
		AtomicBoolean registered = new AtomicBoolean();
		final ObjectName[] bean = new ObjectName[1];
		Runnable unregister = () -> {
			if (registered.compareAndSet(true, false) && bean[0] != null) {
				context.unregister(bean[0]);
			}
		};
		return new ServerMain.Service() {
			@Override
			public String name() {
				return s.name();
			}

			@Override
			public void startAndWait(long timeoutMillis) throws IOException {
				s.startAndWait(timeoutMillis);
				if (registered.compareAndSet(false, true)) {
					try {
						bean[0] = context.register("MailQueue", id, new MailQueueBean(server.getQueue(), server.getQueueHistory()));
					} catch (JMException | RuntimeException e) {
						System.err.println("Can't register the queue's JMX bean: " + e);
					}
				}
			}

			@Override
			public int port() {
				return s.port();
			}

			@Override
			public void stop(long timeoutMillis) throws InterruptedException {
				try {
					s.stop(timeoutMillis);
				} finally {
					unregister.run();
				}
			}

			@Override
			public void awaitStop() throws InterruptedException {
				s.awaitStop();
				unregister.run();
			}

			@Override
			public int connections() {
				return s.connections();
			}

			@Override
			public java.util.List<us.bringardner.parley.net.server.ParleyConnection> connectionList() {
				return s.connectionList();
			}
		};
	}

	/** {@code parley.mail.smtp.secure=true}: the relay with implicit TLS (on parley.mail.smtps.port) */
	static boolean legacySecure(Properties configuration) {
		String v = configuration.getProperty(SmtpServer.SMTP_PREFIX + ".secure");
		return v != null && Boolean.parseBoolean(v.trim());
	}

	/** The relay (MX, port 25): {@code smtp}, on unless parley.mail.smtp.port is 0 */
	public static final class Smtp extends MailServerProvider {
		public Smtp() {
			super("smtp", "SMTP relay (MX)", "parley-smtp.properties", SmtpServer.CONFIG_PROP);
		}

		@Override
		public int port(Properties configuration) {
			return intProperty(configuration, (legacySecure(configuration) ? SmtpServer.SMTPS_PREFIX : SmtpServer.SMTP_PREFIX) + ".port", SMTP.SMTP_PORT);
		}

		@Override
		public ServerMain.Service create(ServerContext context, Properties configuration) throws Exception {
			int port = port(configuration);
			boolean secure = legacySecure(configuration);
			SmtpServer s = AbstractMailServer.makeIn(context, configuration, () -> new SmtpServer(port, SmtpServer.SMTP_NAME, secure, false));
			return service(s, id(), "SMTP server", context);
		}
	}

	/** Submission (RFC 6409, port 587, STARTTLS): {@code submission}, on unless parley.mail.submission.port is 0 */
	public static final class Submission extends MailServerProvider {
		public Submission() {
			super("submission", "SMTP submission", "parley-smtp.properties", SmtpServer.CONFIG_PROP);
		}

		@Override
		public int port(Properties configuration) {
			return intProperty(configuration, SmtpServer.SUBMISSION_PREFIX + ".port", SMTP.SUBMISSION_PORT);
		}

		@Override
		public ServerMain.Service create(ServerContext context, Properties configuration) throws Exception {
			int port = port(configuration);
			SmtpServer s = AbstractMailServer.makeIn(context, configuration, () -> new SmtpServer(port, SmtpServer.SMTP_NAME, false, true));
			return service(s, id(), "Submission server", context);
		}
	}

	/**
	 * Submission with implicit TLS (RFC 8314, port 465): {@code submissions}, on when
	 * parley.mail.submissions.port is set (and not 0)
	 */
	public static final class Submissions extends MailServerProvider {
		public Submissions() {
			super("submissions", "SMTP submission with implicit TLS", "parley-smtp.properties", SmtpServer.CONFIG_PROP);
		}

		@Override
		public int port(Properties configuration) {
			return intProperty(configuration, SmtpServer.SUBMISSIONS_PREFIX + ".port", 0);
		}

		@Override
		public ServerMain.Service create(ServerContext context, Properties configuration) throws Exception {
			int port = port(configuration);
			SmtpServer s = AbstractMailServer.makeIn(context, configuration, () -> new SmtpServer(port, SmtpServer.SMTP_NAME, true, true));
			return service(s, id(), "Submission server (implicit TLS)", context);
		}
	}
}
