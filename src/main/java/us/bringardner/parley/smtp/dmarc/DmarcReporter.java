package us.bringardner.parley.smtp.dmarc;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.dns.resolve.LookupResult;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.HeaderFields;
import us.bringardner.parley.smtp.spf.SpfResult;

/**
 * Sends DMARC reports to the domains that ask for them.
 * <ul>
 * <li><b>Aggregate reports</b> (rua=, RFC 7489 section 7.2): each evaluation
 * is appended to a file per policy domain (under the maildrop root, so it
 * survives restarts); every report interval the files become XML reports,
 * gzipped and mailed.</li>
 * <li><b>Failure reports</b> (ruf=, section 7.3): sent at once in the Abuse
 * Reporting Format (RFC 6591) with the message's header (not its body), when
 * the domain's fo= options call for one, at most a few per domain per hour.</li>
 * </ul>
 * A report address in another organization's domain is used only if that
 * domain agrees to receive the reports (section 7.1: a v=DMARC1 TXT record at
 * &lt;policy domain&gt;._report._dmarc.&lt;report domain&gt;).
 */
public final class DmarcReporter {

	/** Queues a report message (the server: MailQueue.enqueue). */
	@FunctionalInterface
	public interface Sender {
		void send(String from, List<String> to, byte[] message) throws IOException;
	}

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final Pattern MAILTO = Pattern.compile("(?i)mailto:([^!?]+)(?:\\?[^!]*)?(?:!([0-9]+)([kmgt]?))?");

	private volatile boolean aggregate;
	private volatile boolean failure;
	private volatile String orgName = "localhost";
	private volatile String email = "postmaster@localhost";
	private volatile String hostname = "localhost";
	private volatile long intervalMillis = 24L * 3600 * 1000;
	private volatile int maxFailurePerHour = 10;
	private volatile LongSupplier clock = System::currentTimeMillis;
	private final Map<String, Deque<Long>> failureTimes = new HashMap<>();
	private final Object fileLock = new Object();

	private DmarcDns dns;
	private PublicSuffixList psl;
	private FileSource dir;
	private Sender sender;
	private ScheduledExecutorService timer;

	// ------------------------------------------------------------------ settings

	public boolean isAggregate() {
		return aggregate;
	}

	/** Send aggregate reports (default false). */
	public void setAggregate(boolean aggregate) {
		this.aggregate = aggregate;
	}

	public boolean isFailure() {
		return failure;
	}

	/** Send failure reports (default false). */
	public void setFailure(boolean failure) {
		this.failure = failure;
	}

	/** report_metadata/org_name and the Submitter in the subject. */
	public void setOrgName(String orgName) {
		this.orgName = orgName;
	}

	public String getOrgName() {
		return orgName;
	}

	/** The reports' From address and report_metadata/email. */
	public void setEmail(String email) {
		this.email = email;
	}

	public String getEmail() {
		return email;
	}

	/** This server's name (Message-ID, Reporting-MTA). */
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	/** How often aggregate reports are sent (default 24 hours). */
	public void setIntervalMillis(long intervalMillis) {
		this.intervalMillis = Math.max(60_000, intervalMillis);
	}

	public long getIntervalMillis() {
		return intervalMillis;
	}

	/** Failure reports per policy domain per hour (default 10). */
	public void setMaxFailurePerHour(int max) {
		this.maxFailurePerHour = Math.max(0, max);
	}

	/** For tests. */
	public void setClock(LongSupplier clock) {
		this.clock = clock;
	}

	// ------------------------------------------------------------------ life cycle

	/**
	 * Start sending: reports are kept in {@code dir} and sent with {@code sender}.
	 * A second call while running does nothing.
	 */
	public synchronized void start(FileSource dir, Sender sender, DmarcDns dns, PublicSuffixList psl) throws IOException {
		if (timer != null) {
			return;
		}
		if (!dir.exists()) {
			dir.mkdirs();
		}
		this.dir = dir;
		this.sender = sender;
		this.dns = dns;
		this.psl = psl;
		timer = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "DmarcReporter");
			t.setDaemon(true);
			return t;
		});
		timer.scheduleAtFixedRate(this::flushQuietly, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
	}

	/** Stop the timer; stored evaluations are kept for the next start. */
	public synchronized void stop() {
		if (timer != null) {
			timer.shutdownNow();
			timer = null;
		}
	}

	public synchronized boolean isRunning() {
		return timer != null;
	}

	// ------------------------------------------------------------------ evaluations

	/**
	 * Report one DMARC evaluation (a message with a policy that passed or
	 * failed): store it for the aggregate report and, if called for, send a
	 * failure report.
	 *
	 * @param dmarc        the result
	 * @param source       the client's address
	 * @param envelopeFrom the reverse-path (null for &lt;&gt;)
	 * @param spf          the SPF result (null if not checked)
	 * @param dkim         the DKIM results
	 * @param applied      what was done: none (delivered), quarantine or reject
	 * @param headers      the message's header (for a failure report)
	 * @param authResults  the Authentication-Results value
	 */
	public void evaluated(DmarcResult dmarc, InetAddress source, String envelopeFrom, SpfResult spf, List<DkimResult> dkim,
			DmarcRecord.Policy applied, HeaderFields headers, String authResults) {
		evaluated(dmarc, source, envelopeFrom, spf, dkim, applied, headers, authResults, null);
	}

	/**
	 * Report one DMARC evaluation whose policy was overridden for a known
	 * reason, e.g. a trusted ARC chain (RFC 8617 section 7.2.2).
	 *
	 * @param overrideComment the comment of the local_policy override (null for the default)
	 * @see #evaluated(DmarcResult, InetAddress, String, SpfResult, List, DmarcRecord.Policy, HeaderFields, String)
	 */
	public void evaluated(DmarcResult dmarc, InetAddress source, String envelopeFrom, SpfResult spf, List<DkimResult> dkim,
			DmarcRecord.Policy applied, HeaderFields headers, String authResults, String overrideComment) {
		if (dmarc == null || dmarc.getRecord() == null || (!aggregate && !failure) || dir == null) {
			return;
		}
		DmarcRecord rec = dmarc.getRecord();
		if (aggregate && !rec.getAggregateReports().isEmpty()) {
			store(record(dmarc, source, envelopeFrom, spf, dkim, applied, overrideComment, clock.getAsLong()));
		}
		if (failure && !rec.getFailureReports().isEmpty() && wantsFailureReport(dmarc, spf, dkim) && !isReport(headers)
				&& allowFailure(dmarc.getPolicyDomain())) {
			try {
				sendFailure(dmarc, source, envelopeFrom, dkim, applied, headers, authResults);
			} catch (IOException | RuntimeException e) {
				// best effort: a report must never affect the message
			}
		}
	}

	/** The aggregate report row for an evaluation. */
	static ReportRecord record(DmarcResult dmarc, InetAddress source, String envelopeFrom, SpfResult spf, List<DkimResult> dkim,
			DmarcRecord.Policy applied, long now) {
		return record(dmarc, source, envelopeFrom, spf, dkim, applied, null, now);
	}

	static ReportRecord record(DmarcResult dmarc, InetAddress source, String envelopeFrom, SpfResult spf, List<DkimResult> dkim,
			DmarcRecord.Policy applied, String overrideComment, long now) {
		String reason = "";
		String comment = "";
		if (applied != dmarc.getDisposition() && overrideComment != null) {
			reason = "local_policy";
			comment = overrideComment;
		} else if (dmarc.getResult() == DmarcResult.Result.FAIL && dmarc.getDisposition() != dmarc.getPolicy()) {
			reason = "sampled_out";
		} else if (applied != dmarc.getDisposition()) {
			reason = "local_policy";
			comment = "policy not enforced";
		}
		List<ReportRecord.Dkim> auth = new ArrayList<>();
		for (DkimResult r : dkim) {
			if (r.getResult() != DkimResult.Result.NONE) {
				auth.add(new ReportRecord.Dkim(r.getDomain() == null ? "" : r.getDomain(), r.getSelector() == null ? "" : r.getSelector(),
						r.getResult().keyword()));
			}
		}
		String spfDomain;
		String scope;
		String spfResult;
		if (spf != null) {
			spfDomain = spf.getDomain();
			scope = spf.getIdentity() == SpfResult.Identity.HELO ? "helo" : "mfrom";
			spfResult = spf.getResult().keyword();
		} else {
			spfDomain = envelopeFrom == null ? "" : envelopeFrom.substring(envelopeFrom.lastIndexOf('@') + 1);
			scope = "mfrom";
			spfResult = "none";
		}
		String raw = String.join("; ", tagList(dmarc.getRecord()));
		return new ReportRecord(now / 1000, source == null ? "" : source.getHostAddress(), dmarc.getFromDomain(), envelopeFrom,
				dmarc.getPolicyDomain(), raw, applied.keyword(), dmarc.getDkimDomain() != null ? "pass" : "fail",
				dmarc.isSpfAligned() ? "pass" : "fail", reason, comment, auth, spfDomain, scope, spfResult);
	}

	private static List<String> tagList(DmarcRecord r) {
		List<String> ret = new ArrayList<>();
		for (Map.Entry<String, String> e : r.getTags().entrySet()) {
			ret.add(e.getKey() + "=" + e.getValue().replace(";", ""));
		}
		if (!r.getTags().containsKey("v")) {
			ret.add(0, "v=DMARC1");
		}
		return ret;
	}

	private void store(ReportRecord r) {
		synchronized (fileLock) {
			try (OutputStream out = file(r.getPolicyDomain(), ".log").getOutputStream(true)) {
				out.write(r.toLine().getBytes(StandardCharsets.UTF_8));
			} catch (IOException e) {
				// best effort
			}
		}
	}

	private FileSource file(String domain, String ext) throws IOException {
		return dir.getChild(domain.replaceAll("[^a-z0-9._-]", "_") + ext);
	}

	// ------------------------------------------------------------------ aggregate reports

	private void flushQuietly() {
		try {
			flush();
		} catch (IOException | RuntimeException e) {
			// try again next time
		}
	}

	/**
	 * Send the aggregate reports for everything stored so far, one per policy
	 * domain.
	 *
	 * @return the number of report messages queued
	 */
	public int flush() throws IOException {
		if (dir == null) {
			return 0;
		}
		List<FileSource> batches = new ArrayList<>();
		synchronized (fileLock) {
			for (FileSource f : dir.listFiles()) {
				String n = f.getName();
				if (n.endsWith(".log")) {
					FileSource s = dir.getChild(n.substring(0, n.length() - 4) + "." + Long.toString(clock.getAsLong(), 36) + ".sending");
					if (f.renameTo(s)) {
						batches.add(s);
					}
				} else if (n.endsWith(".sending")) {
					batches.add(f); // left over from an earlier run
				}
			}
		}
		int sent = 0;
		for (FileSource f : batches) {
			List<ReportRecord> records = new ArrayList<>();
			try (BufferedReader r = new BufferedReader(new InputStreamReader(f.getInputStream(), StandardCharsets.UTF_8))) {
				String line;
				while ((line = r.readLine()) != null) {
					ReportRecord rec = ReportRecord.fromLine(line);
					if (rec != null) {
						records.add(rec);
					}
				}
			}
			if (!records.isEmpty()) {
				sent += sendAggregate(records);
			}
			f.delete();
		}
		return sent;
	}

	private int sendAggregate(List<ReportRecord> records) throws IOException {
		String domain = records.get(0).getPolicyDomain();
		DmarcRecord policy = null;
		long begin = Long.MAX_VALUE;
		long end = clock.getAsLong() / 1000;
		for (ReportRecord r : records) {
			begin = Math.min(begin, r.getTime());
			DmarcRecord p = DmarcRecord.parse(r.policyRecord);
			if (p != null) {
				policy = p;
			}
		}
		if (policy == null) {
			return 0;
		}
		String id = safe(orgName) + "." + safe(domain) + "." + end + "." + Long.toHexString(RANDOM.nextLong() & 0xffffffffL);
		String xml = AggregateReport.xml(orgName, email, id, begin, end, domain, records);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (GZIPOutputStream gz = new GZIPOutputStream(bytes)) {
			gz.write(xml.getBytes(StandardCharsets.UTF_8));
		}
		byte[] gzipped = bytes.toByteArray();
		String fileName = safe(orgName) + "!" + safe(domain) + "!" + begin + "!" + end + ".xml.gz";
		List<String> to = new ArrayList<>();
		for (String uri : policy.getAggregateReports()) {
			String addr = destination(uri, domain, gzipped.length + gzipped.length / 3 + 2048);
			if (addr != null && !to.contains(addr)) {
				to.add(addr);
			}
		}
		if (to.isEmpty()) {
			return 0;
		}
		sender.send(email, to, ReportMail.aggregate(email, to, hostname, orgName, domain, id, fileName, gzipped, begin, end));
		return 1;
	}

	private static String safe(String s) {
		return s.replaceAll("[^A-Za-z0-9._-]", "_");
	}

	/**
	 * The address of a mailto: report URI, if it may be used: it fits the
	 * size limit (the "!10m" suffix), and a domain outside the policy domain's
	 * organization has agreed to receive reports for it (section 7.1).
	 *
	 * @return the address, or null
	 */
	String destination(String uri, String policyDomain, long size) {
		Matcher m = MAILTO.matcher(uri.trim());
		if (!m.matches()) {
			return null; // only mailto: is supported
		}
		String addr = decode(m.group(1)).trim();
		int at = addr.lastIndexOf('@');
		if (at <= 0 || at == addr.length() - 1) {
			return null;
		}
		if (m.group(2) != null) {
			long limit;
			try {
				limit = Long.parseLong(m.group(2));
			} catch (NumberFormatException e) {
				return null;
			}
			String unit = m.group(3).toLowerCase(Locale.ROOT);
			int shift = unit.isEmpty() ? 0 : 10 * ("kmgt".indexOf(unit) + 1);
			if (shift > 0 && limit > (Long.MAX_VALUE >> shift)) {
				limit = Long.MAX_VALUE;
			} else {
				limit <<= shift;
			}
			if (size > limit) {
				return null;
			}
		}
		String target = addr.substring(at + 1).toLowerCase(Locale.ROOT);
		PublicSuffixList list = psl != null ? psl : PublicSuffixList.getDefault();
		String orgTarget = list.organizationalDomain(target);
		String orgPolicy = list.organizationalDomain(policyDomain);
		if (orgTarget == null || !orgTarget.equals(orgPolicy)) {
			LookupResult<String> r;
			try {
				r = dns.txt(policyDomain + "._report._dmarc." + target);
			} catch (RuntimeException e) {
				return null;
			}
			boolean ok = false;
			for (String t : r.getValues()) {
				ok |= DmarcRecord.isDmarc(t);
			}
			if (!ok) {
				return null;
			}
		}
		return addr;
	}

	private static String decode(String s) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '%' && i + 2 < s.length()) {
				try {
					out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
					i += 2;
					continue;
				} catch (NumberFormatException e) {
					// a literal '%'
				}
			}
			byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
			out.write(b, 0, b.length);
		}
		return new String(out.toByteArray(), StandardCharsets.UTF_8);
	}

	// ------------------------------------------------------------------ failure reports

	/** The fo= options (section 6.3): 0 (default), 1, d and s. */
	static boolean wantsFailureReport(DmarcResult dmarc, SpfResult spf, List<DkimResult> dkim) {
		String fo = dmarc.getRecord().getTags().getOrDefault("fo", "0");
		String rf = dmarc.getRecord().getTags().getOrDefault("rf", "afrf");
		boolean afrf = false;
		for (String f : rf.split(":")) {
			afrf |= f.trim().equalsIgnoreCase("afrf");
		}
		if (!afrf) {
			return false;
		}
		boolean dkimAligned = dmarc.getDkimDomain() != null;
		boolean spfAligned = dmarc.isSpfAligned();
		for (String o : fo.split(":")) {
			switch (o.trim().toLowerCase(Locale.ROOT)) {
			case "0":
				if (!dkimAligned && !spfAligned) {
					return true;
				}
				break;
			case "1":
				if (!dkimAligned || !spfAligned) {
					return true;
				}
				break;
			case "d":
				for (DkimResult r : dkim) {
					if (r.getResult() == DkimResult.Result.FAIL) {
						return true;
					}
				}
				break;
			case "s":
				if (spf != null && spf.getResult() == SpfResult.Result.FAIL) {
					return true;
				}
				break;
			default:
				break;
			}
		}
		return false;
	}

	/** Never report on a report (two servers could otherwise send them back and forth). */
	static boolean isReport(HeaderFields headers) {
		if (headers == null) {
			return false;
		}
		HeaderFields.Field ct = headers.get("Content-Type");
		return ct != null && ct.getValue().toLowerCase(Locale.ROOT).replace(" ", "").contains("report-type=feedback-report");
	}

	private boolean allowFailure(String domain) {
		long now = clock.getAsLong();
		synchronized (failureTimes) {
			Deque<Long> times = failureTimes.computeIfAbsent(domain, k -> new ArrayDeque<>());
			while (!times.isEmpty() && times.peekFirst() < now - 3_600_000L) {
				times.pollFirst();
			}
			if (times.size() >= maxFailurePerHour) {
				return false;
			}
			times.addLast(now);
			return true;
		}
	}

	private void sendFailure(DmarcResult dmarc, InetAddress source, String envelopeFrom, List<DkimResult> dkim,
			DmarcRecord.Policy applied, HeaderFields headers, String authResults) throws IOException {
		String domain = dmarc.getPolicyDomain();
		ByteArrayOutputStream head = new ByteArrayOutputStream();
		if (headers != null) {
			for (HeaderFields.Field f : headers.getFields()) {
				byte[] b = f.getRaw().getBytes(StandardCharsets.ISO_8859_1);
				head.write(b, 0, b.length);
			}
		}
		List<String> to = new ArrayList<>();
		for (String uri : dmarc.getRecord().getFailureReports()) {
			String addr = destination(uri, domain, head.size() + 4096);
			if (addr != null && !to.contains(addr)) {
				to.add(addr);
			}
		}
		if (to.isEmpty()) {
			return;
		}
		List<String> aligned = new ArrayList<>();
		if (dmarc.getDkimDomain() != null) {
			aligned.add("dkim");
		}
		if (dmarc.isSpfAligned()) {
			aligned.add("spf");
		}
		String ip = source == null ? "unknown" : source.getHostAddress();
		String delivery = applied == DmarcRecord.Policy.REJECT ? "reject" : applied == DmarcRecord.Policy.QUARANTINE ? "spam" : "delivered";
		StringBuilder fb = new StringBuilder();
		fb.append("Feedback-Type: auth-failure\r\n");
		fb.append("User-Agent: Parley\r\n");
		fb.append("Version: 1\r\n");
		fb.append("Original-Mail-From: <").append(envelopeFrom == null ? "" : ReportMail.clean(envelopeFrom)).append(">\r\n");
		fb.append("Arrival-Date: ").append(new us.bringardner.parley.mail.Rfc2822Date()).append("\r\n");
		fb.append("Reporting-MTA: dns; ").append(hostname).append("\r\n");
		fb.append("Source-IP: ").append(ip).append("\r\n");
		fb.append("Reported-Domain: ").append(dmarc.getFromDomain()).append("\r\n");
		if (authResults != null) {
			fb.append("Authentication-Results: ").append(ReportMail.clean(authResults)).append("\r\n");
		}
		fb.append("Identity-Alignment: ").append(aligned.isEmpty() ? "none" : String.join(", ", aligned)).append("\r\n");
		fb.append("Auth-Failure: dmarc\r\n");
		fb.append("Delivery-Result: ").append(delivery).append("\r\n");
		for (DkimResult r : dkim) {
			if (r.getResult() == DkimResult.Result.FAIL && r.getDomain() != null) {
				fb.append("DKIM-Domain: ").append(r.getDomain()).append("\r\n");
				if (r.getSelector() != null) {
					fb.append("DKIM-Selector: ").append(r.getSelector()).append("\r\n");
				}
				break;
			}
		}
		String text = "This is an authentication failure report for a message received from " + ip + " with From domain "
				+ dmarc.getFromDomain() + ".\r\nThe message did not pass DMARC" + (dmarc.isPass() ? " for every mechanism" : "")
				+ "; it was " + delivery + ". Its header is attached.";
		sender.send(email, to, ReportMail.failure(email, to, hostname, dmarc.getFromDomain(), text, fb.toString(), head.toByteArray()));
	}
}
