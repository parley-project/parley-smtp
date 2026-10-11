package us.bringardner.parley.smtp.queue;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.sasl.ISaslClient;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.MailPath;
import us.bringardner.parley.io.IoUtils;

/**
 * Hands a queued message to the next server for a domain: the domain's MX hosts
 * in order of preference (or the configured smart host), with opportunistic
 * STARTTLS, and the SIZE, 8BITMIME, SMTPUTF8, CHUNKING, BINARYMIME and DSN
 * extensions where the message needs them.
 */
public final class RemoteDelivery {

	/** What happened to one recipient. */
	public static final class Result {
		/** Null if the next server accepted the recipient. */
		public final DeliveryException error;
		public final String remoteMta;
		/** True if the next server took over DSN (it supports the DSN extension). */
		public final boolean dsnPassedOn;

		Result(DeliveryException error, String remoteMta, boolean dsnPassedOn) {
			this.error = error;
			this.remoteMta = remoteMta;
			this.dsnPassedOn = dsnPassedOn;
		}
	}

	/** A failure of the whole connection: try the next host. */
	private static final class HostFailure extends Exception {
		private static final long serialVersionUID = 1L;
		final DeliveryException cause;

		HostFailure(DeliveryException cause) {
			this.cause = cause;
		}
	}

	private final DeliveryConfig config;

	public RemoteDelivery(DeliveryConfig config) {
		this.config = config;
	}

	/** Deliver to recipients in one domain (or, with a smart host, any domains). */
	public Map<QueuedRecipient, Result> deliver(QueueEntry entry, FileSource content, List<QueuedRecipient> rcpts,
			String domain) {
		Map<QueuedRecipient, Result> results = new LinkedHashMap<>();
		boolean smartHost = config.getRelayHost() != null;
		List<MxResolver.Route> routes;
		try {
			routes = smartHost ? List.of(new MxResolver.Route(config.getRelayHost(), config.getRelayPort()))
					: config.getResolver().resolve(domain, config.getRemotePort());
		} catch (DeliveryException e) {
			for (QueuedRecipient r : rcpts) {
				results.put(r, new Result(e, null, false));
			}
			return results;
		}
		DeliveryException last = DeliveryException.temporary("4.4.1", "No servers for " + domain);
		for (MxResolver.Route route : routes) {
			try {
				return attempt(entry, content, rcpts, route, smartHost, true);
			} catch (HostFailure f) {
				last = f.cause;
				if (last.isPermanent()) {
					break;
				}
			}
		}
		for (QueuedRecipient r : rcpts) {
			results.put(r, new Result(last, last.getRemoteMta(), false));
		}
		return results;
	}

	private static DeliveryException fromReply(SmtpClient.Reply reply, String host, String what) {
		boolean permanent = reply.code >= 500;
		String status = reply.enhanced();
		if (status == null || status.charAt(0) != (permanent ? '5' : '4')) {
			status = permanent ? "5.0.0" : "4.0.0";
		}
		return new DeliveryException(permanent, status, host + " said " + reply + " (" + what + ")", "smtp; " + reply,
				"dns; " + host);
	}

	private Map<QueuedRecipient, Result> attempt(QueueEntry entry, FileSource content, List<QueuedRecipient> rcpts,
			MxResolver.Route route, boolean smartHost, boolean allowTls) throws HostFailure {
		String mta = "dns; " + route.host;
		DeliveryConfig.TlsMode tlsMode = smartHost ? config.getRelayTlsMode() : config.getTlsMode();
		SmtpClient c;
		try {
			c = new SmtpClient(route.host, route.address, route.port, config.getConnectTimeout(), config.getReadTimeout());
		} catch (IOException e) {
			throw new HostFailure(new DeliveryException(false, "4.4.1", "Can't connect to " + route + ": " + e.getMessage(),
					null, mta));
		}
		try {
			SmtpClient.Reply r = c.readReply();
			if (r.code != 220) {
				// try the next host, whatever the code (RFC 5321 section 3.1)
				throw new HostFailure(new DeliveryException(false, "4.4.1", route.host + " refused the connection: " + r,
						"smtp; " + r, mta));
			}
			r = c.hello(config.getHostname());
			if (r.code != 250) {
				throw new HostFailure(fromReply(r, route.host, "EHLO"));
			}
			if (tlsMode != DeliveryConfig.TlsMode.NONE && allowTls && c.supports("STARTTLS")) {
				try {
					r = c.startTls(tlsMode == DeliveryConfig.TlsMode.REQUIRED);
					if (r.code != 220) {
						if (tlsMode == DeliveryConfig.TlsMode.REQUIRED) {
							throw new HostFailure(fromReply(r, route.host, "STARTTLS"));
						}
					} else {
						r = c.hello(config.getHostname());
						if (r.code != 250) {
							throw new HostFailure(fromReply(r, route.host, "EHLO after STARTTLS"));
						}
					}
				} catch (IOException e) {
					if (tlsMode == DeliveryConfig.TlsMode.REQUIRED) {
						throw new HostFailure(new DeliveryException(false, "4.7.0", "TLS with " + route.host + " failed: "
								+ e.getMessage(), null, mta));
					}
					// opportunistic: try again without TLS
					IoUtils.closeQuietly(c);
					return attempt(entry, content, rcpts, route, smartHost, false);
				}
			} else if (tlsMode == DeliveryConfig.TlsMode.REQUIRED) {
				throw new HostFailure(new DeliveryException(false, "4.7.0", route.host + " doesn't offer STARTTLS", null, mta));
			}
			if (smartHost && config.getRelayUser() != null) {
				String password = config.getRelayPassword() == null ? "" : config.getRelayPassword();
				ISaslClient sasl = config.getRelayAuthMechanisms().isEmpty() ? null
						: c.chooseSasl(config.getRelayUser(), password, config.getRelayAuthMechanisms());
				r = sasl != null ? c.authenticate(sasl) : c.authPlain(config.getRelayUser(), password);
				if (r.code != 235) {
					throw new HostFailure(new DeliveryException(false, "4.7.0", "The smart host refused the login: " + r,
							"smtp; " + r, mta));
				}
			}
			return transaction(c, entry, content, rcpts, route.host, mta);
		} catch (IOException e) {
			throw new HostFailure(new DeliveryException(false, "4.4.2", "Connection to " + route + " failed: " + e.getMessage(),
					null, mta));
		} finally {
			IoUtils.closeQuietly(c);
		}
	}

	private Map<QueuedRecipient, Result> transaction(SmtpClient c, QueueEntry entry, FileSource content,
			List<QueuedRecipient> rcpts, String host, String mta) throws IOException, HostFailure {
		Map<QueuedRecipient, Result> results = new LinkedHashMap<>();
		boolean needsUtf8 = entry.smtpUtf8 || (entry.from != null && entry.from.needsSmtpUtf8());
		for (QueuedRecipient q : rcpts) {
			needsUtf8 |= q.address.needsSmtpUtf8();
		}
		DeliveryException refuse = null;
		if (needsUtf8 && !c.supports("SMTPUTF8")) {
			refuse = new DeliveryException(true, "5.6.7", host + " doesn't support SMTPUTF8, which the message needs", null, mta);
		} else if (entry.body == QueueEntry.Body.EIGHT_BIT && !c.supports("8BITMIME")) {
			refuse = new DeliveryException(true, "5.6.3", host + " doesn't accept 8-bit content", null, mta);
		} else if (entry.body == QueueEntry.Body.BINARY && !(c.supports("CHUNKING") && c.supports("BINARYMIME"))) {
			refuse = new DeliveryException(true, "5.6.3", host + " doesn't accept binary content", null, mta);
		} else if (c.supports("SIZE")) {
			try {
				long max = Long.parseLong(c.getExtensions().get("SIZE").trim());
				if (max > 0 && entry.size > max) {
					refuse = new DeliveryException(true, "5.3.4", "The message is larger than " + host + " accepts (" + max
							+ " bytes)", null, mta);
				}
			} catch (NumberFormatException e) {
				// no limit given
			}
		}
		if (refuse != null) {
			for (QueuedRecipient q : rcpts) {
				results.put(q, new Result(refuse, mta, false));
			}
			c.quit();
			return results;
		}
		boolean dsn = c.supports("DSN");
		StringBuilder mail = new StringBuilder("MAIL FROM:<");
		if (entry.from != null) {
			mail.append(needsUtf8 ? entry.from : entry.from.toAsciiDomain());
		}
		mail.append('>');
		if (c.supports("SIZE")) {
			mail.append(" SIZE=").append(entry.size);
		}
		if (entry.body != QueueEntry.Body.SEVEN_BIT) {
			mail.append(" BODY=").append(entry.body.keyword);
		}
		if (needsUtf8) {
			mail.append(" SMTPUTF8");
		}
		if (dsn) {
			if (entry.ret != null) {
				mail.append(" RET=").append(entry.ret);
			}
			if (entry.envid != null) {
				mail.append(" ENVID=").append(MailPath.encodeXtext(entry.envid));
			}
		}
		SmtpClient.Reply r = c.command(mail.toString());
		if (r.code != 250) {
			DeliveryException e = fromReply(r, host, "MAIL FROM");
			if (!e.isPermanent()) {
				throw new HostFailure(e);
			}
			for (QueuedRecipient q : rcpts) {
				results.put(q, new Result(e, mta, false));
			}
			c.quit();
			return results;
		}
		List<QueuedRecipient> accepted = new ArrayList<>();
		for (QueuedRecipient q : rcpts) {
			MailAddress a = needsUtf8 ? q.address : q.address.toAsciiDomain();
			StringBuilder rcpt = new StringBuilder("RCPT TO:<").append(a).append('>');
			if (dsn) {
				if (q.notify != null) {
					rcpt.append(" NOTIFY=").append(QueuedRecipient.formatNotify(q.notify));
				}
				if (q.orcpt != null) {
					int semi = q.orcpt.indexOf(';');
					rcpt.append(" ORCPT=").append(semi > 0 ? q.orcpt.substring(0, semi) + ";"
							+ MailPath.encodeXtext(q.orcpt.substring(semi + 1)) : "rfc822;" + MailPath.encodeXtext(q.orcpt));
				}
			}
			r = c.command(rcpt.toString());
			if (r.code == 250 || r.code == 251) {
				accepted.add(q);
			} else {
				results.put(q, new Result(fromReply(r, host, "RCPT TO"), mta, false));
			}
		}
		if (accepted.isEmpty()) {
			c.quit();
			return results;
		}
		try (InputStream in = IoUtils.buffered(content.getInputStream())) {
			r = entry.body == QueueEntry.Body.BINARY ? c.bdat(in, content.length()) : c.data(in);
		}
		DeliveryException failed = r.code == 250 ? null : fromReply(r, host, "end of data");
		for (QueuedRecipient q : accepted) {
			results.put(q, new Result(failed, mta, failed == null && dsn));
		}
		c.quit();
		return results;
	}

}
