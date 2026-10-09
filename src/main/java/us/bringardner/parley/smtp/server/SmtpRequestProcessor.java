package us.bringardner.parley.smtp.server;

import us.bringardner.parley.io.LineTooLongException;
import java.io.BufferedOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.core.ILogger;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.mail.Rfc2822Date;
import us.bringardner.parley.net.IConnection;
import us.bringardner.parley.mail.server.AbstractMailProcessor;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.SMTP;
import us.bringardner.parley.smtp.SmtpInput;
import us.bringardner.parley.smtp.SmtpStreams;
import us.bringardner.parley.smtp.dkim.ArcResult;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.smtp.queue.HeaderRewriter;
import us.bringardner.parley.smtp.queue.MailQueue;
import us.bringardner.parley.smtp.queue.QueueEntry;
import us.bringardner.parley.smtp.queue.QueuedRecipient;
import us.bringardner.parley.smtp.queue.DeliveryConfig;
import us.bringardner.parley.smtp.dmarc.DmarcRecord;
import us.bringardner.parley.smtp.dmarc.DmarcResult;
import us.bringardner.parley.smtp.spf.Spf;
import us.bringardner.parley.smtp.spf.SpfResult;
import us.bringardner.parley.io.IoUtils;

/**
 * One SMTP session (RFC 5321). Like the FTP, POP3 and IMAP processors it runs
 * command classes from {@link SmtpCommandFactory}; it reads the socket itself
 * so message content (DATA, BDAT) is streamed into the queue as bytes.
 * <p>
 * Replies are flushed only when no more pipelined commands are waiting
 * (PIPELINING, RFC 2920).
 */
public class SmtpRequestProcessor extends AbstractMailProcessor implements SMTP {

	private static final long serialVersionUID = 1L;

	private static final int MAX_COMMAND_LINE = 4096;
	private static final int MAX_ERRORS = 20;
	private static final int POLL_INTERVAL = 1000;
	private static final SecureRandom RANDOM = new SecureRandom();

	/** The connection is gone (as opposed to a failure in the queue). */
	static final class ConnectionLostException extends IOException {
		private static final long serialVersionUID = 1L;

		ConnectionLostException(IOException cause) {
			super(cause.getMessage(), cause);
		}
	}

	/** A mail transaction: MAIL, RCPTs and content (RFC 5321 section 3.3). */
	public static final class Transaction {
		public MailAddress from;
		public long declaredSize = -1;
		public QueueEntry.Body body = QueueEntry.Body.SEVEN_BIT;
		public boolean smtpUtf8;
		public String ret;
		public String envid;
		public final List<QueuedRecipient> recipients = new ArrayList<>();
		/** The SPF result of MAIL FROM (null if not checked). */
		public SpfResult spf;
		/** BDAT in progress. */
		String id;
		FileSource incoming;
		OutputStream out;
		long chunked;
		boolean tooLarge;
		public boolean bdatUsed;
	}

	private transient SmtpInput in;
	private transient OutputStream out;
	private String helo;
	private boolean esmtp;
	private Transaction transaction;
	private int errors;
	private volatile boolean closing;

	public SmtpRequestProcessor() {
		super();
		setCommandFactory(new SmtpCommandFactory());
		setName("SmtpRequestProcessor");
		setPropertyPrefix("SmtpRequestProcessor");
	}

	public SmtpServer getSmtpServer() {
		return (SmtpServer) getServer();
	}

	// ------------------------------------------------------------------ session loop

	@Override
	public void run() {
		running = true;
		IConnection con = getConnection();
		try {
			openStreams();
			reply(SERVICE_READY, null, getSmtpServer().getHostname() + " ESMTP Parley ready");
			flush();
			loop();
		} catch (ConnectionLostException | SocketException e) {
			// the client went away
		} catch (Throwable e) {
			logError("An error occurred in the SMTP session; closing the connection.", e);
		} finally {
			abortTransaction();
			running = false;
			try {
				getServer().removeClient(this);
			} catch (RuntimeException e) {
				// ignore
			}
			IoUtils.closeQuietly(con);
		}
	}

	private void loop() throws IOException {
		while (running && !stopping && !closing) {
			byte[] raw;
			try {
				raw = in.readLine(MAX_COMMAND_LINE);
			} catch (SocketTimeoutException e) {
				if (!stopping) {
					reply(SERVICE_NOT_AVAILABLE, "4.4.2", getSmtpServer().getHostname() + " Error: timeout exceeded");
					flush();
				}
				return;
			} catch (LineTooLongException e) {
				error(SYNTAX_ERROR, "5.5.6", "Line too long");
				continue;
			}
			if (raw == null) {
				return;
			}
			String line = new String(raw, StandardCharsets.UTF_8);
			processLine(line, null);
			if (!in.hasBuffered() || closing) {
				flush();
			}
		}
		if (stopping && !closing) {
			reply(SERVICE_NOT_AVAILABLE, "4.3.2", getSmtpServer().getHostname() + " Service shutting down");
			flush();
		}
	}

	@Override
	protected void processLine(String line, Map<String, String> cmdUsed) throws IOException {
		int sp = line.indexOf(' ');
		String verb = (sp < 0 ? line : line.substring(0, sp)).toUpperCase(Locale.ROOT);
		String args = sp < 0 ? "" : line.substring(sp + 1);
		if (isDebugEnabled()) {
			logDebug("Received command=" + verb);
		}
		if (verb.isEmpty()) {
			error(SYNTAX_ERROR, "5.5.2", "Syntax error: empty command");
			return;
		}
		ICommand command = ((SmtpCommandFactory) getCommandFactory()).getCommand(verb);
		if (!(command instanceof SmtpCommand)) {
			if (verb.endsWith(":") || verb.equals("GET") || verb.equals("POST")) {
				// an HTTP or other non-SMTP client
				reply(SERVICE_NOT_AVAILABLE, "4.7.0", "This is an SMTP server; closing the connection");
				closing = true;
				return;
			}
			error(SYNTAX_ERROR, "5.5.2", "Command unrecognized: " + sanitize(verb));
			return;
		}
		try {
			((SmtpCommand) command).execute(this, args);
		} catch (ConnectionLostException e) {
			throw e;
		} catch (IllegalArgumentException e) {
			error(PARAMETER_ERROR, "5.5.4", "Syntax error in parameters: " + sanitize(e.getMessage()));
		} catch (IOException e) {
			logError("Error in " + verb, e);
			reply(LOCAL_ERROR, "4.3.0", "Local error in processing; try again later");
		} catch (RuntimeException e) {
			logError("Error in " + verb, e);
			reply(LOCAL_ERROR, "4.3.0", "Local error in processing; try again later");
		}
	}

	/** Reply with an error, closing the connection after too many. */
	public void error(int code, String enhanced, String text) throws IOException {
		if (++errors >= MAX_ERRORS) {
			reply(SERVICE_NOT_AVAILABLE, "4.7.0", "Too many errors; closing the connection");
			closing = true;
			return;
		}
		reply(code, enhanced, text);
	}

	static String sanitize(String text) {
		if (text == null) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < text.length() && sb.length() < 60; i++) {
			char c = text.charAt(i);
			sb.append(c < 32 || c == 127 ? '?' : c);
		}
		return sb.toString();
	}

	private void openStreams() throws IOException {
		Socket s = getConnection().getSocket();
		s.setSoTimeout(POLL_INTERVAL);
		InputStream rawIn = s.getInputStream();
		OutputStream rawOut = s.getOutputStream();
		in = new SmtpInput(new java.io.FilterInputStream(rawIn) {
			@Override
			public int read(byte[] b, int off, int len) throws IOException {
				try {
					return super.read(b, off, len);
				} catch (SocketTimeoutException e) {
					throw e;
				} catch (IOException e) {
					throw new ConnectionLostException(e);
				}
			}
		});
		in.setKeepWaiting(() -> !stopping && running
				&& System.currentTimeMillis() - in.getLastReceived() < getSmtpServer().getTimeout());
		out = new BufferedOutputStream(new FilterOutputStream(rawOut) {
			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				try {
					out.write(b, off, len);
				} catch (IOException e) {
					throw new ConnectionLostException(e);
				}
			}

			@Override
			public void flush() throws IOException {
				try {
					out.flush();
				} catch (IOException e) {
					throw new ConnectionLostException(e);
				}
			}
		}, 16 * 1024);
	}

	// ------------------------------------------------------------------ replies

	/** "code enhanced text" (the enhanced status code may be null). */
	public void reply(int code, String enhanced, String text) throws IOException {
		out.write((code + " " + (enhanced == null ? "" : enhanced + " ") + text + "\r\n").getBytes(StandardCharsets.UTF_8));
	}

	/** A multi-line reply: "code-line" ... "code line". */
	public void reply(int code, List<String> lines) throws IOException {
		for (int i = 0; i < lines.size(); i++) {
			out.write((code + (i + 1 < lines.size() ? "-" : " ") + lines.get(i) + "\r\n").getBytes(StandardCharsets.UTF_8));
		}
	}

	@Override
	public void reply(String text) throws IOException {
		out.write((text + "\r\n").getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public String translateResponseCode(int code) {
		return String.valueOf(code);
	}

	public void flush() throws IOException {
		out.flush();
	}

	/** Read one line from the client (AUTH responses); null at end of stream. */
	public String readLine() throws IOException {
		flush();
		byte[] b = in.readLine(MAX_COMMAND_LINE);
		return b == null ? null : new String(b, StandardCharsets.UTF_8);
	}

	public SmtpInput getInput() {
		return in;
	}

	/** End the session after the current reply (QUIT). */
	public void close() {
		closing = true;
	}

	// ------------------------------------------------------------------ session state

	public String getHelo() {
		return helo;
	}

	/** EHLO or HELO: a new session state, with any transaction reset. */
	public void hello(String name, boolean esmtp) {
		this.helo = name;
		this.esmtp = esmtp;
		abortTransaction();
	}

	public boolean isEsmtp() {
		return esmtp;
	}

	public boolean isAuthenticated() {
		return getPrincipal() != null;
	}

	public InetAddress getClientAddress() {
		return getConnection().getSocket().getInetAddress();
	}

	/** True if the client may send to non-local domains. */
	public boolean mayRelay() {
		return isAuthenticated() || getSmtpServer().isRelayAllowed(getClientAddress());
	}

	public Transaction getTransaction() {
		return transaction;
	}

	/** MAIL: start a transaction. */
	public void setTransaction(Transaction t) {
		abortTransaction();
		transaction = t;
	}

	/** RSET, a new EHLO, or the end of the session: forget the transaction. */
	public void abortTransaction() {
		Transaction t = transaction;
		transaction = null;
		if (t != null && t.incoming != null) {
			try {
				if (t.out != null) {
					t.out.close();
				}
			} catch (IOException e) {
				// ignore
			}
			try {
				t.incoming.delete();
			} catch (IOException e) {
				// ignore
			}
		}
	}

	public MailQueue getQueue() {
		return getSmtpServer().getQueue();
	}

	/** STARTTLS: negotiate TLS and forget everything known about the client (RFC 3207 section 4.2). */
	@Override
	protected void beforeTls() throws IOException {
		flush();
	}

	@Override
	protected void afterTls() throws IOException {
		openStreams();
		helo = null;
		esmtp = false;
		setPrincipal(null);
		abortTransaction();
	}

	// ------------------------------------------------------------------ AUTH

	/**
	 * Check a user name and password (SASLprep'd, RFC 4013). The user needs the
	 * WRITE permission to send mail.
	 */
	public boolean login(String user, String password) {
		IPrincipal p = authenticate(user, password);
		if (p == null || !getServer().isAuthorized(p, SmtpCommand.SEND_PERMISSION)) {
			return false;
		}
		setPrincipal(p);
		return true;
	}

	/** Reply to a failed AUTH; the connection is closed after too many. */
	public void authFailed() throws IOException {
		loginFailedDelay();
		if (tooManyLoginFailures()) {
			reply(SERVICE_NOT_AVAILABLE, "4.7.0", "Too many authentication failures");
			closing = true;
		} else {
			reply(AUTH_FAILED, "5.7.8", "Authentication credentials invalid");
		}
	}

	// ------------------------------------------------------------------ message content

	/** The protocol for the Received header (RFC 3848, RFC 6531). */
	private String protocol(Transaction t) {
		String p = t.smtpUtf8 ? "UTF8SMTP" : esmtp ? "ESMTP" : "SMTP";
		if (!t.smtpUtf8 && !esmtp) {
			return p;
		}
		if (isTls()) {
			p += "S";
		}
		if (isAuthenticated()) {
			p += "A";
		}
		return p;
	}

	/** Start the content of a transaction: the queue file with our Received header. */
	private void openContent(Transaction t) throws IOException {
		t.id = MailQueue.newId();
		t.incoming = getQueue().incoming(t.id);
		t.out = IoUtils.buffered(t.incoming.getOutputStream());
		String client = getClientAddress().getHostAddress();
		if (client.indexOf(':') >= 0) {
			int zone = client.indexOf('%');
			client = "IPv6:" + (zone > 0 ? client.substring(0, zone) : client);
		}
		StringBuilder r = new StringBuilder("Received: from ").append(helo == null ? "unknown" : sanitize(helo))
				.append(" ([").append(client).append("])\r\n\tby ").append(getSmtpServer().getHostname())
				.append(" (Parley) with ").append(protocol(t)).append(" id ").append(t.id);
		if (t.recipients.size() == 1) {
			r.append("\r\n\tfor <").append(t.recipients.get(0).getAddress()).append('>');
		}
		r.append("; ").append(new Rfc2822Date()).append("\r\n");
		t.out.write(r.toString().getBytes(StandardCharsets.UTF_8));
	}

	/** DATA: read the content, queue the message and reply. */
	public void receiveData(Transaction t) throws IOException {
		openContent(t);
		SmtpInput.DataResult result;
		SmtpStreams.CrlfOutputStream crlf = new SmtpStreams.CrlfOutputStream(t.out);
		try {
			result = in.readData(crlf, getSmtpServer().getMaxMessageSize());
			crlf.finish();
		} finally {
			t.out.close();
			t.out = null;
		}
		if (result.tooLarge) {
			abortTransaction();
			reply(EXCEEDED_STORAGE, "5.3.4", "Message size exceeds fixed limit");
			return;
		}
		finish(t);
	}

	/** BDAT: one chunk; the last one queues the message. */
	public void receiveChunk(Transaction t, long size, boolean last) throws IOException {
		if (t.out == null && !t.tooLarge) {
			openContent(t);
		}
		t.bdatUsed = true;
		long max = getSmtpServer().getMaxMessageSize();
		if (t.tooLarge || t.chunked + size > max) {
			t.tooLarge = true;
			in.readFully(size, null);
		} else {
			in.readFully(size, t.out);
			t.chunked += size;
		}
		if (!last) {
			if (t.tooLarge) {
				reply(EXCEEDED_STORAGE, "5.3.4", "Message size exceeds fixed limit");
				abortTransaction();
			} else {
				reply(OK, "2.0.0", size + " octets received");
			}
			return;
		}
		if (t.tooLarge) {
			abortTransaction();
			reply(EXCEEDED_STORAGE, "5.3.4", "Message size exceeds fixed limit");
			return;
		}
		t.out.close();
		t.out = null;
		if (t.body != QueueEntry.Body.BINARY) {
			normalize(t);
		}
		finish(t);
	}

	/** Make a BDAT message's line ends CRLF (except BINARYMIME content). */
	private void normalize(Transaction t) throws IOException {
		FileSource src = t.incoming;
		FileSource dst = getQueue().incoming(t.id + "n");
		try (InputStream i = IoUtils.buffered(src.getInputStream());
				OutputStream o = IoUtils.buffered(dst.getOutputStream());
				SmtpStreams.CrlfOutputStream c = new SmtpStreams.CrlfOutputStream(o)) {
			i.transferTo(c);
		}
		src.delete();
		if (!dst.renameTo(src)) {
			throw new IOException("Can't store the message");
		}
	}

	/** Check the headers, add submission headers, queue the message and reply 250. */
	private void finish(Transaction t) throws IOException {
		HeaderScan scan = HeaderScan.of(t.incoming);
		if (scan.received > getSmtpServer().getMaxHops()) {
			abortTransaction();
			reply(TRANSACTION_FAILED, "5.4.6", "Too many hops; a mail loop?");
			return;
		}
		if (getSmtpServer().isSubmission() && (!scan.date || !scan.messageId)) {
			// RFC 6409 section 8.2 and 8.3
			StringBuilder add = new StringBuilder();
			if (!scan.date) {
				add.append("Date: ").append(new Rfc2822Date()).append("\r\n");
			}
			if (!scan.messageId) {
				add.append("Message-ID: <").append(t.id).append('.').append(Long.toHexString(RANDOM.nextLong() & Long.MAX_VALUE))
						.append('@').append(getSmtpServer().getHostname()).append(">\r\n");
			}
			insertAfterTrace(t, add.toString());
		}
		boolean quarantine = false;
		if (mayRelay()) {
			// our own users' mail: sign it with the key of its From domain, if any
			getQueue().dkimSign(t.id, t.incoming);
		} else {
			AuthResults auth = addAuthenticationResults(t);
			DmarcResult dmarc = auth == null ? null : auth.dmarc;
			DmarcRecord.Policy applied = DmarcRecord.Policy.NONE;
			String override = null;
			if (dmarc != null && dmarc.getResult() == DmarcResult.Result.FAIL && getQueue().getConfig().getDmarc().isEnforce()) {
				applied = dmarc.getDisposition();
				if (applied != DmarcRecord.Policy.NONE && trustedArc(auth.arc)) {
					// a trusted intermediary vouches for the original authentication (RFC 8617 section 7.2)
					applied = DmarcRecord.Policy.NONE;
					override = auth.arc.toReportComment();
				}
			}
			if (dmarc != null) {
				report(t, auth, applied, override);
			}
			if (applied == DmarcRecord.Policy.REJECT) {
				abortTransaction();
				reply(MAILBOX_UNAVAILABLE, "5.7.1", "Rejected by the DMARC policy of " + dmarc.getFromDomain());
				return;
			}
			quarantine = applied == DmarcRecord.Policy.QUARANTINE;
		}
		QueueEntry e = new QueueEntry(t.id);
		e.setQuarantine(quarantine);
		e.setInbound(!mayRelay());
		e.setFrom(t.from);
		e.setBody(t.body);
		e.setSmtpUtf8(t.smtpUtf8);
		e.setRet(t.ret);
		e.setEnvid(t.envid);
		e.setSize(t.incoming.length());
		e.setSubmitter(isAuthenticated() ? getPrincipal().getName() : null);
		for (QueuedRecipient r : t.recipients) {
			e.addRecipient(r);
		}
		FileSource incoming = t.incoming;
		t.incoming = null;
		transaction = null;
		try {
			getQueue().commit(e, incoming);
		} catch (IOException ex) {
			incoming.delete();
			throw ex;
		}
		reply(OK, "2.0.0", "Ok: queued as " + t.id);
	}

	/**
	 * SPF (RFC 7208) for MAIL FROM, or for the HELO name when the
	 * reverse-path is null. Null if SPF checking is off or the client is
	 * authenticated or trusted.
	 */
	public SpfResult checkSpf(MailAddress from) {
		Spf spf = getQueue().getConfig().getSpf();
		if (!spf.isCheck() || mayRelay()) {
			return null;
		}
		try {
			String sender = from == null ? null : from.getLocalPart() + "@" + from.getAsciiDomain();
			return spf.checker(getSmtpServer().getHostname()).checkMailFrom(getClientAddress(), sender, helo);
		} catch (RuntimeException e) {
			logError("SPF check failed", e);
			return null;
		}
	}

	/**
	 * Record the SPF result (Received-SPF, RFC 7208 section 9.1), verify the
	 * message's DKIM signatures, evaluate DMARC (RFC 7489), and put the results
	 * in an Authentication-Results field (RFC 8601) after our Received field.
	 * Authentication-Results and Received-SPF fields that claim to be from
	 * this server are removed (section 5).
	 *
	 * @return the results (null if nothing is checked)
	 */
	private AuthResults addAuthenticationResults(Transaction t) throws IOException {
		DeliveryConfig config = getQueue().getConfig();
		boolean dkim = config.getDkim().isVerify();
		boolean dmarcOn = config.getDmarc().isCheck();
		boolean arcOn = config.getArc().isVerify();
		if (t.spf == null && !dkim && !dmarcOn && !arcOn) {
			return null;
		}
		String host = getSmtpServer().getHostname();
		List<DkimResult> results = new ArrayList<>();
		if (dkim) {
			try (InputStream i = IoUtils.buffered(t.incoming.getInputStream())) {
				results = config.getDkim().verify(i);
			} catch (IOException | RuntimeException e) {
				logError("DKIM verification of " + t.id + " failed", e);
			}
		}
		ArcResult arc = null;
		if (arcOn) {
			try (InputStream i = IoUtils.buffered(t.incoming.getInputStream())) {
				arc = config.getArc().verifier(config.getDkim()).verify(i);
			} catch (IOException | RuntimeException e) {
				logError("ARC validation of " + t.id + " failed", e);
			}
		}
		DmarcResult dmarc = null;
		HeaderFields headers = null;
		if (dmarcOn) {
			try (InputStream i = IoUtils.buffered(t.incoming.getInputStream())) {
				headers = HeaderFields.read(i);
				dmarc = config.getDmarc().checker().check(headers, t.spf, results);
			} catch (IOException | RuntimeException e) {
				logError("DMARC check of " + t.id + " failed", e);
			}
		}
		StringBuilder fields = new StringBuilder();
		if (t.spf != null) {
			fields.append("Received-SPF: ").append(t.spf.toReceivedSpf(host)).append("\r\n");
		}
		StringBuilder ar = new StringBuilder("Authentication-Results: ").append(host);
		if (t.spf != null) {
			ar.append(";\r\n\t").append(t.spf.toAuthResults());
		}
		if (dkim) {
			for (DkimResult r : results) {
				ar.append(";\r\n\t").append(r.toAuthResults());
			}
		}
		if (dmarc != null) {
			ar.append(";\r\n\t").append(dmarc.toAuthResults());
		}
		if (arc != null) {
			// the chain status our seal records (cv=) when the message is forwarded
			ar.append(";\r\n\t").append(arc.toAuthResults(clientIp()));
		}
		fields.append(ar).append("\r\n");
		HeaderRewriter.insertAfterFirst(t.incoming, getQueue().incoming(t.id + "a"), fields.toString(),
				f -> (f.is("Authentication-Results") && host.equalsIgnoreCase(authServId(f.getValue())))
						|| (f.is("Received-SPF") && t.spf != null && claimsReceiver(f.getValue(), host)));
		return new AuthResults(dmarc, results, arc, headers, ar.substring("Authentication-Results: ".length()));
	}

	/** The client's address without an IPv6 zone. */
	private String clientIp() {
		String ip = getClientAddress().getHostAddress();
		int zone = ip.indexOf('%');
		return zone > 0 ? ip.substring(0, zone) : ip;
	}

	/** True if a chain passed and its newest seal is from a trusted sealer (organizational domains compared). */
	private boolean trustedArc(ArcResult arc) {
		if (arc == null || !arc.isPass()) {
			return false;
		}
		DeliveryConfig config = getQueue().getConfig();
		List<String> trusted = config.getArc().getTrustedSealers();
		if (trusted.isEmpty()) {
			return false;
		}
		us.bringardner.parley.smtp.dmarc.PublicSuffixList psl = config.getDmarc().getPublicSuffixList();
		String sealer = psl.organizationalDomain(arc.getLatestSealDomain());
		if (sealer == null) {
			return false;
		}
		for (String d : trusted) {
			if (sealer.equalsIgnoreCase(psl.organizationalDomain(d))) {
				return true;
			}
		}
		return false;
	}

	/** What addAuthenticationResults found. */
	private static final class AuthResults {
		final DmarcResult dmarc;
		final List<DkimResult> dkim;
		final ArcResult arc;
		final HeaderFields headers;
		final String authResults;

		AuthResults(DmarcResult dmarc, List<DkimResult> dkim, ArcResult arc, HeaderFields headers, String authResults) {
			this.dmarc = dmarc;
			this.dkim = dkim;
			this.arc = arc;
			this.headers = headers;
			this.authResults = authResults;
		}
	}

	/** Pass a DMARC evaluation to the reporter (aggregate and failure reports). */
	private void report(Transaction t, AuthResults auth, DmarcRecord.Policy applied, String override) {
		try {
			String from = t.from == null ? null : t.from.getLocalPart() + "@" + t.from.getAsciiDomain();
			getQueue().getConfig().getDmarc().getReporter().evaluated(auth.dmarc, getClientAddress(), from, t.spf, auth.dkim, applied,
					auth.headers, auth.authResults, override);
		} catch (RuntimeException e) {
			logError("DMARC report for " + t.id + " failed", e);
		}
	}

	/** True if a Received-SPF value names this server as the receiver (a forged one). */
	static boolean claimsReceiver(String value, String host) {
		String v = value.toLowerCase(java.util.Locale.ROOT);
		String h = host.toLowerCase(java.util.Locale.ROOT);
		return v.contains("receiver=" + h + ";") || v.contains("receiver=" + h + " ") || v.endsWith("receiver=" + h)
				|| v.contains("(" + h + ":");
	}

	/** The authserv-id of an Authentication-Results value: the text before the first ';' (version and comments removed). */
	static String authServId(String value) {
		String v = HeaderFields.stripComments(value);
		int semi = v.indexOf(';');
		String id = (semi < 0 ? v : v.substring(0, semi)).trim();
		int sp = id.indexOf(' ');
		return sp < 0 ? id : id.substring(0, sp); // "host 1" has a version
	}

	/** Add header lines after our Received header (the first header). */
	private void insertAfterTrace(Transaction t, String headers) throws IOException {
		FileSource src = t.incoming;
		FileSource dst = getQueue().incoming(t.id + "h");
		try (InputStream i = IoUtils.buffered(src.getInputStream());
				OutputStream o = IoUtils.buffered(dst.getOutputStream())) {
			copyInsertingAfterTrace(i, o, headers.getBytes(StandardCharsets.UTF_8));
		}
		src.delete();
		if (!dst.renameTo(src)) {
			throw new IOException("Can't store the message");
		}
	}

	/**
	 * Copy {@code in} to {@code out} with {@code added} after the first header field
	 * (the field ends at the first line that doesn't start with white space), a block at a time.
	 */
	static void copyInsertingAfterTrace(InputStream in, OutputStream out, byte[] added) throws IOException {
		byte[] buf = new byte[8192];
		int prev = -1;
		boolean done = false;
		int n;
		while (!done && (n = in.read(buf)) > 0) {
			int cut = -1;
			for (int k = 0; k < n; k++) {
				int b = buf[k] & 0xff;
				if (prev == '\n' && b != ' ' && b != '\t') {
					cut = k;
					break;
				}
				prev = b;
			}
			if (cut < 0) {
				out.write(buf, 0, n);
			} else {
				out.write(buf, 0, cut);
				out.write(added);
				out.write(buf, cut, n - cut);
				done = true;
			}
		}
		if (!done) {
			out.write(added);
		}
		in.transferTo(out);
	}

	/** What the header block of a message has. */
	static final class HeaderScan {
		int received;
		boolean date;
		boolean messageId;

		static HeaderScan of(FileSource f) throws IOException {
			try (InputStream in = f.getInputStream()) {
				return of(in);
			}
		}

		/** The header block of the message in {@code in}; stops at the first blank line (or after 4 MB). */
		static HeaderScan of(InputStream in) throws IOException {
			HeaderScan s = new HeaderScan();
			byte[] buf = new byte[8192];
			// only the start of a line matters, and the longest field name we look for is 11 chars
			byte[] head = new byte[12];
			int headLen = 0;
			boolean blank = true;		// nothing but white space so far on this line
			long total = 0;
			int n;
			while (total < MAX_HEADER_SCAN && (n = in.read(buf)) > 0) {
				int end = (int) Math.min(n, MAX_HEADER_SCAN - total);
				total += end;
				for (int k = 0; k < end; k++) {
					byte b = buf[k];
					if (b == '\n') {
						if (blank) {
							return s;
						}
						s.field(head, headLen);
						headLen = 0;
						blank = true;
						continue;
					}
					if ((b & 0xff) > ' ') {
						blank = false;
					}
					if (headLen < head.length) {
						head[headLen++] = b;
					}
				}
			}
			return s;
		}

		private static final long MAX_HEADER_SCAN = 4L * 1024 * 1024;

		private void field(byte[] head, int len) {
			if (startsWith(head, len, "received:")) {
				received++;
			} else if (startsWith(head, len, "date:")) {
				date = true;
			} else if (startsWith(head, len, "message-id:")) {
				messageId = true;
			}
		}

		/** Case-insensitive (ASCII) prefix test; {@code prefix} is lower case. */
		private static boolean startsWith(byte[] b, int len, String prefix) {
			if (len < prefix.length()) {
				return false;
			}
			for (int i = 0; i < prefix.length(); i++) {
				int c = b[i];
				if (c >= 'A' && c <= 'Z') {
					c += 'a' - 'A';
				}
				if (c != prefix.charAt(i)) {
					return false;
				}
			}
			return true;
		}
	}

	@Override
	protected ILogger getLogger(String name) {
		return super.getLogger("SmtpRequestProcessor");
	}
}
