package us.bringardner.parley.smtp.server;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.management.JMException;
import javax.management.ObjectName;

import us.bringardner.parley.mail.server.MailServerProvider;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.smtp.SMTP;
import us.bringardner.parley.smtp.queue.MailQueue;
import us.bringardner.parley.smtp.queue.MailQueueBean;

/**
 * The SMTP servers a launcher can run ({@code parley.servers=smtp,submission,submissions}): the
 * relay (MX, port 25), submission (587) and submission with implicit TLS (465). Settings come from
 * {@code parley-mail.properties}, then {@code parley-smtp.properties} (or the file
 * {@code parley.mail.smtp.configFile} names).
 * <p>
 * The SMTP servers of one JVM share one queue, made from the {@code parley.mail.smtp.*} settings
 * when the first of them starts and let go when the last one stops (so a restart of every SMTP
 * server reads the delivery settings again). While it exists it is the JMX bean
 * {@code us.bringardner.parley:type=MailQueue,name=smtp} ({@link us.bringardner.parley.smtp.queue.MailQueueMXBean}).
 *
 * @since 2.0.0
 */
public final class SmtpProviders {

	/** The key of the {@link SharedQueue} in the {@link ServerContext} */
	public static final String SHARED_QUEUE = "parley.mail.smtp.queue";

	private SmtpProviders() {
	}

	/**
	 * The queue the SMTP servers of a JVM share: its owner is a server that doesn't listen; the
	 * queue lives while one of them runs.
	 */
	public static final class SharedQueue {
		private final ServerContext context;
		private SmtpServer owner;
		private ObjectName bean;
		private int users;

		SharedQueue(ServerContext context) {
			this.context = context;
		}

		synchronized MailQueue acquire() {
			if (owner == null) {
				SmtpServer o = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
				MailQueue q = o.getQueue();
				try {
					bean = context.register("MailQueue", "smtp", new MailQueueBean(q, o.getQueueHistory()));
				} catch (JMException e) {
					System.err.println("Can't register the queue's JMX bean: " + e);
				}
				owner = o;
			}
			users++;
			return owner.getQueue();
		}

		synchronized void release() {
			if (users > 0 && --users == 0) {
				if (bean != null) {
					context.unregister(bean);
					bean = null;
				}
				if (owner.getQueueHistory() != null) {
					owner.getQueueHistory().close();
				}
				owner = null;
			}
		}

		/** The queue while an SMTP server runs, else null */
		public synchronized MailQueue getQueue() {
			return owner == null ? null : owner.getQueue();
		}
	}

	static SharedQueue sharedQueue(ServerContext context) throws Exception {
		return context.shared(SHARED_QUEUE, SharedQueue.class, () -> new SharedQueue(context));
	}

	/** A server using the shared queue: lets go of it when it stops (on request or by itself) */
	static ServerMain.Service service(SmtpServer server, String name, SharedQueue shared) {
		server.setQueue(shared.acquire());
		ServerMain.Service s = ServerMain.service(server, name);
		AtomicBoolean released = new AtomicBoolean();
		Runnable release = () -> {
			if (released.compareAndSet(false, true)) {
				shared.release();
			}
		};
		return new ServerMain.Service() {
			@Override
			public String name() {
				return s.name();
			}

			@Override
			public void startAndWait(long timeoutMillis) throws IOException {
				try {
					s.startAndWait(timeoutMillis);
				} catch (IOException | RuntimeException e) {
					release.run();
					throw e;
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
					release.run();
				}
			}

			@Override
			public void awaitStop() throws InterruptedException {
				s.awaitStop();
				release.run();
			}

			@Override
			public int connections() {
				return s.connections();
			}
		};
	}

	/** {@code parley.mail.smtp.secure=true}: the relay with implicit TLS (on parley.mail.smtps.port) */
	static boolean legacySecure() {
		return Boolean.parseBoolean(System.getProperty(SmtpServer.SMTP_PREFIX + ".secure", "false"));
	}

	/** The relay (MX, port 25): {@code smtp}, on unless parley.mail.smtp.port is 0 */
	public static final class Smtp extends MailServerProvider {
		public Smtp() {
			super("smtp", "SMTP relay (MX)", "parley-smtp.properties", SmtpServer.CONFIG_PROP);
		}

		@Override
		public int port() {
			return intProperty((legacySecure() ? SmtpServer.SMTPS_PREFIX : SmtpServer.SMTP_PREFIX) + ".port", SMTP.SMTP_PORT);
		}

		@Override
		public ServerMain.Service create(ServerContext context) throws Exception {
			return service(new SmtpServer(port(), SmtpServer.SMTP_NAME, legacySecure()), "SMTP server", sharedQueue(context));
		}
	}

	/** Submission (RFC 6409, port 587, STARTTLS): {@code submission}, on unless parley.mail.submission.port is 0 */
	public static final class Submission extends MailServerProvider {
		public Submission() {
			super("submission", "SMTP submission", "parley-smtp.properties", SmtpServer.CONFIG_PROP);
		}

		@Override
		public int port() {
			return intProperty(SmtpServer.SUBMISSION_PREFIX + ".port", SMTP.SUBMISSION_PORT);
		}

		@Override
		public ServerMain.Service create(ServerContext context) throws Exception {
			SmtpServer s = new SmtpServer(port(), SmtpServer.SMTP_NAME, false);
			s.setSubmission(true);
			return service(s, "Submission server", sharedQueue(context));
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
		public int port() {
			return intProperty(SmtpServer.SUBMISSIONS_PREFIX + ".port", 0);
		}

		@Override
		public ServerMain.Service create(ServerContext context) throws Exception {
			SmtpServer s = new SmtpServer(port(), SmtpServer.SMTP_NAME, true);
			s.setSubmission(true);
			return service(s, "Submission server (implicit TLS)", sharedQueue(context));
		}
	}
}
