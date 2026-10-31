package us.bringardner.parley.smtp.spam;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** What a filter is told about a message: the SMTP session it came in on and its content. */
public final class SpamRequest {

	/** Opens the message (headers and body, as received) from the start; called once per scan. */
	@FunctionalInterface
	public interface Content {
		InputStream open() throws IOException;
	}

	private final InetAddress clientAddress;
	private final String helo;
	private final String sender;
	private final List<String> recipients;
	private final String user;
	private final String hostname;
	private final String queueId;
	private final long size;
	private final Content content;

	/**
	 * @param sender the envelope sender ("" for a bounce)
	 * @param recipients the envelope recipients this scan is for
	 * @param user the login of the client, or null
	 * @param hostname this server's name
	 */
	public SpamRequest(InetAddress clientAddress, String helo, String sender, List<String> recipients, String user,
			String hostname, String queueId, long size, Content content) {
		this.clientAddress = clientAddress;
		this.helo = helo;
		this.sender = sender == null ? "" : sender;
		this.recipients = Collections.unmodifiableList(new ArrayList<>(recipients));
		this.user = user;
		this.hostname = hostname;
		this.queueId = queueId;
		this.size = size;
		this.content = content;
	}

	public InetAddress getClientAddress() {
		return clientAddress;
	}

	/** The name the client gave in HELO/EHLO, or null. */
	public String getHelo() {
		return helo;
	}

	public String getSender() {
		return sender;
	}

	public List<String> getRecipients() {
		return recipients;
	}

	/** The login of the client, or null if it did not authenticate. */
	public String getUser() {
		return user;
	}

	public String getHostname() {
		return hostname;
	}

	public String getQueueId() {
		return queueId;
	}

	/** The size of the message in bytes. */
	public long getSize() {
		return size;
	}

	/** The message, from the start. */
	public InputStream openMessage() throws IOException {
		return content.open();
	}

	/** The same message and session for other recipients. */
	SpamRequest forRecipients(List<String> other) {
		return new SpamRequest(clientAddress, helo, sender, other, user, hostname, queueId, size, content);
	}
}
