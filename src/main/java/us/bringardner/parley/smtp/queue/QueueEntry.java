package us.bringardner.parley.smtp.queue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.smtp.MailAddress;

/**
 * A message in the queue: the envelope (RFC 5321 reverse-path, recipients and
 * ESMTP parameters) in {@code <id>.env}, the content in {@code <id>.eml}.
 */
public final class QueueEntry {

	static final String HEADER = "BJLQUEUE 1";

	/** BODY parameter values (RFC 6152, RFC 3030). */
	public enum Body {
		SEVEN_BIT("7BIT"), EIGHT_BIT("8BITMIME"), BINARY("BINARYMIME");

		public final String keyword;

		Body(String keyword) {
			this.keyword = keyword;
		}

		public static Body parse(String s) {
			for (Body b : values()) {
				if (b.keyword.equalsIgnoreCase(s)) {
					return b;
				}
			}
			throw new IllegalArgumentException("Unknown BODY " + s);
		}
	}

	final String id;
	long created = System.currentTimeMillis();
	/** The reverse-path, or null for {@code <>} (bounces). */
	MailAddress from;
	String envid;
	/** RET: "FULL", "HDRS" or null. */
	String ret;
	Body body = Body.SEVEN_BIT;
	boolean smtpUtf8;
	long size;
	/** Who submitted it (authenticated user), or null. */
	String submitter;
	/** Deliver locally to the Junk mailbox, not INBOX (a DMARC quarantine policy). */
	boolean quarantine;
	/** Received from another server (not submitted by a user or trusted client): forwarded copies are ARC-sealed. */
	boolean inbound;
	/** Our ARC set has been added. */
	boolean arcSealed;
	final List<QueuedRecipient> recipients = new ArrayList<>();

	public QueueEntry(String id) {
		this.id = id;
	}

	public String getId() {
		return id;
	}

	public long getCreated() {
		return created;
	}

	public MailAddress getFrom() {
		return from;
	}

	public void setFrom(MailAddress from) {
		this.from = from;
	}

	public String getEnvid() {
		return envid;
	}

	public void setEnvid(String envid) {
		this.envid = envid;
	}

	public String getRet() {
		return ret;
	}

	public void setRet(String ret) {
		this.ret = ret;
	}

	public Body getBody() {
		return body;
	}

	public void setBody(Body body) {
		this.body = body;
	}

	public boolean isSmtpUtf8() {
		return smtpUtf8;
	}

	public void setSmtpUtf8(boolean smtpUtf8) {
		this.smtpUtf8 = smtpUtf8;
	}

	public long getSize() {
		return size;
	}

	public void setSize(long size) {
		this.size = size;
	}

	public String getSubmitter() {
		return submitter;
	}

	public void setSubmitter(String submitter) {
		this.submitter = submitter;
	}

	public boolean isQuarantine() {
		return quarantine;
	}

	/** Local delivery goes to the recipient's Junk mailbox (DMARC p=quarantine). */
	public void setQuarantine(boolean quarantine) {
		this.quarantine = quarantine;
	}

	public boolean isInbound() {
		return inbound;
	}

	/** The message came from another server; copies forwarded to other servers get an ARC set (RFC 8617). */
	public void setInbound(boolean inbound) {
		this.inbound = inbound;
	}

	public boolean isArcSealed() {
		return arcSealed;
	}

	public List<QueuedRecipient> getRecipients() {
		return recipients;
	}

	public void addRecipient(QueuedRecipient r) {
		recipients.add(r);
	}

	/** True while some recipient hasn't been delivered or given up. */
	public boolean isPending() {
		for (QueuedRecipient r : recipients) {
			if (r.status == QueuedRecipient.Status.PENDING) {
				return true;
			}
		}
		return false;
	}

	/** The earliest time a pending recipient should be tried, or Long.MAX_VALUE. */
	public long nextAttempt() {
		long n = Long.MAX_VALUE;
		for (QueuedRecipient r : recipients) {
			if (r.status == QueuedRecipient.Status.PENDING) {
				n = Math.min(n, r.nextAttempt);
			}
		}
		return n;
	}

	// ------------------------------------------------------------------ persistence

	private static String clean(String s) {
		return s == null ? "" : s.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
	}

	void write(FileSource file) throws IOException {
		FileSource tmp = file.getParentFile().getChild("." + file.getName() + ".tmp");
		try (Writer w = new OutputStreamWriter(tmp.getOutputStream(), StandardCharsets.UTF_8)) {
			w.write(HEADER + "\n");
			w.write("ID\t" + id + "\n");
			w.write("CREATED\t" + created + "\n");
			w.write("FROM\t" + (from == null ? "" : from.toString()) + "\n");
			w.write("ENVID\t" + clean(envid) + "\n");
			w.write("RET\t" + clean(ret) + "\n");
			w.write("BODY\t" + body.keyword + "\n");
			w.write("UTF8\t" + (smtpUtf8 ? "1" : "0") + "\n");
			w.write("SIZE\t" + size + "\n");
			w.write("SUBMITTER\t" + clean(submitter) + "\n");
			if (quarantine) {
				w.write("QUARANTINE\t1\n");
			}
			if (inbound) {
				w.write("INBOUND\t1\n");
			}
			if (arcSealed) {
				w.write("ARC\t1\n");
			}
			for (QueuedRecipient r : recipients) {
				w.write("R\t" + r.address + "\t" + r.status + "\t" + r.attempts + "\t" + r.nextAttempt + "\t"
						+ QueuedRecipient.formatNotify(r.notify) + "\t" + (r.delayNotified ? "1" : "0") + "\t" + clean(r.orcpt)
						+ "\t" + clean(r.lastStatus) + "\t" + clean(r.lastResult) + "\t" + clean(r.remoteMta) + "\t" + r.depth
						+ "\n");
			}
		}
		if (file.exists()) {
			file.delete();
		}
		if (!tmp.renameTo(file)) {
			throw new IOException("Can't write " + file.getAbsolutePath());
		}
	}

	static QueueEntry read(FileSource file) throws IOException {
		QueueEntry e = null;
		try (BufferedReader r = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
			String line = r.readLine();
			if (!HEADER.equals(line)) {
				throw new IOException("Not a queue file: " + file.getAbsolutePath());
			}
			while ((line = r.readLine()) != null) {
				String[] p = line.split("\t", -1);
				String v = p.length > 1 ? p[1] : "";
				if (p[0].equals("ID")) {
					e = new QueueEntry(v);
					continue;
				}
				if (e == null) {
					throw new IOException("Queue file without ID: " + file.getAbsolutePath());
				}
				switch (p[0]) {
				case "CREATED":
					e.created = Long.parseLong(v);
					break;
				case "FROM":
					e.from = v.isEmpty() ? null : MailAddress.parse(v, true);
					break;
				case "ENVID":
					e.envid = v.isEmpty() ? null : v;
					break;
				case "RET":
					e.ret = v.isEmpty() ? null : v;
					break;
				case "BODY":
					e.body = Body.parse(v);
					break;
				case "UTF8":
					e.smtpUtf8 = "1".equals(v);
					break;
				case "SIZE":
					e.size = Long.parseLong(v);
					break;
				case "SUBMITTER":
					e.submitter = v.isEmpty() ? null : v;
					break;
				case "QUARANTINE":
					e.quarantine = "1".equals(v);
					break;
				case "INBOUND":
					e.inbound = "1".equals(v);
					break;
				case "ARC":
					e.arcSealed = "1".equals(v);
					break;
				case "R": {
					QueuedRecipient q = new QueuedRecipient(MailAddress.parse(p[1], true), p[7].isEmpty() ? null : p[7],
							p[5].isEmpty() ? null : QueuedRecipient.parseNotify(p[5]));
					q.status = QueuedRecipient.Status.valueOf(p[2]);
					q.attempts = Integer.parseInt(p[3]);
					q.nextAttempt = Long.parseLong(p[4]);
					q.delayNotified = "1".equals(p[6]);
					q.lastStatus = p[8];
					q.lastResult = p[9];
					q.remoteMta = p[10].isEmpty() ? null : p[10];
					q.depth = Integer.parseInt(p[11]);
					e.recipients.add(q);
					break;
				}
				default:
					// ignore unknown lines
				}
			}
		} catch (RuntimeException ex) {
			throw new IOException("Damaged queue file " + file.getAbsolutePath(), ex);
		}
		if (e == null) {
			throw new IOException("Empty queue file " + file.getAbsolutePath());
		}
		return e;
	}

	@Override
	public String toString() {
		return id + " from <" + (from == null ? "" : from) + "> to " + recipients;
	}
}
