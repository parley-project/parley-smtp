package us.bringardner.parley.smtp.queue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

/**
 * The history of a mail queue: every {@link QueueEvent} as a JSON line, one file per day
 * ({@code smtp-YYYY-MM-DD.jsonl}), files older than the days kept deleted. The queue forgets a
 * message once it's done; this is where a person (or an admin tool) looks afterwards.
 * <p>
 * A line has {@code time} (ms), {@code type}, {@code id}, {@code from}, then either
 * {@code recipients} (QUEUED, COMPLETED, DELETED) or {@code recipient}, {@code status},
 * {@code result}, {@code remoteMta}, {@code attempts} and {@code nextAttempt}, then {@code size},
 * {@code submitter} and {@code inbound}. Servers in several processes sharing a queue append to the
 * same files, a line at a time.
 *
 * @since 2.0.0
 */
public final class QueueHistory implements QueueListener {

	/** Writes the history (default true) */
	public static final String HISTORY_PROP = "parley.mail.smtp.queue.history";
	/** The history's folder (default: .smtp-history in the mail root) */
	public static final String DIRECTORY_PROP = "parley.mail.smtp.queue.historyDirectory";
	/** Days of history kept (default 30; 0 keeps every day) */
	public static final String DAYS_PROP = "parley.mail.smtp.queue.historyDays";
	/** The folder's name in the mail root */
	public static final String DEFAULT_DIRECTORY = ".smtp-history";
	public static final String PREFIX = "smtp-";
	public static final String SUFFIX = ".jsonl";

	private static final System.Logger LOG = System.getLogger(QueueHistory.class.getName());

	private final File dir;
	private final int keepDays;
	private final ZoneId zone = ZoneId.systemDefault();
	private LocalDate openDay;
	private OutputStream out;

	public QueueHistory(File dir, int keepDays) {
		this.dir = dir;
		this.keepDays = keepDays;
	}

	/**
	 * The history the settings ask for, or null when it's turned off (or the mail root isn't a
	 * local folder and no folder is set).
	 *
	 * @param mailRoot the mail root's path, or null when it isn't a local folder
	 */
	public static QueueHistory fromSettings(String mailRoot) {
		if (!Boolean.parseBoolean(System.getProperty(HISTORY_PROP, "true"))) {
			return null;
		}
		String d = System.getProperty(DIRECTORY_PROP);
		File folder = d != null && !d.trim().isEmpty() ? new File(d.trim()) : mailRoot == null ? null : new File(mailRoot, DEFAULT_DIRECTORY);
		if (folder == null) {
			return null;
		}
		return new QueueHistory(folder, Integer.getInteger(DAYS_PROP, 30));
	}

	public File getDirectory() {
		return dir;
	}

	/** The file of one day */
	public File file(LocalDate day) {
		return new File(dir, PREFIX + day + SUFFIX);
	}

	@Override
	public void queueEvent(QueueEvent event) {
		try {
			append(event.getTime(), toJson(event));
		} catch (IOException | RuntimeException e) {
			LOG.log(System.Logger.Level.WARNING, "Can't record " + event + " in the queue history " + dir, e);
		}
	}

	private synchronized void append(long time, String json) throws IOException {
		LocalDate day = Instant.ofEpochMilli(time).atZone(zone).toLocalDate();
		if (out == null || !day.equals(openDay)) {
			close();
			if (!dir.isDirectory() && !dir.mkdirs()) {
				throw new IOException("Can't create " + dir);
			}
			out = new FileOutputStream(file(day), true);
			openDay = day;
			prune(day);
		}
		out.write((json + "\n").getBytes(StandardCharsets.UTF_8));
		out.flush();
	}

	/** Delete the files of days before those kept */
	private void prune(LocalDate today) {
		if (keepDays <= 0) {
			return;
		}
		String oldest = PREFIX + today.minusDays(keepDays) + SUFFIX;
		File[] files = dir.listFiles((d, n) -> n.startsWith(PREFIX) && n.endsWith(SUFFIX)
				&& n.length() == oldest.length() && n.compareTo(oldest) < 0);
		if (files != null) {
			for (File f : files) {
				if (!f.delete()) {
					LOG.log(System.Logger.Level.WARNING, "Can't delete the old queue history " + f);
				}
			}
		}
	}

	public synchronized void close() {
		if (out != null) {
			try {
				out.close();
			} catch (IOException e) {
				// nothing to do
			}
			out = null;
		}
	}

	/** An event as the JSON line written */
	public static String toJson(QueueEvent e) {
		StringBuilder b = new StringBuilder(256).append('{');
		field(b, "time", e.getTime());
		field(b, "type", e.getType().name());
		field(b, "id", e.getId());
		field(b, "from", e.getFrom());
		if (e.getRecipient() != null) {
			field(b, "recipient", e.getRecipient());
			field(b, "status", e.getStatus());
			field(b, "result", e.getResult());
			if (e.getRemoteMta() != null) {
				field(b, "remoteMta", e.getRemoteMta());
			}
			field(b, "attempts", e.getAttempts());
			if (e.getNextAttempt() > 0) {
				field(b, "nextAttempt", e.getNextAttempt());
			}
		} else {
			field(b, "recipients", e.getRecipients());
		}
		field(b, "size", e.getSize());
		if (e.getSubmitter() != null) {
			field(b, "submitter", e.getSubmitter());
		}
		field(b, "inbound", e.isInbound());
		return b.append('}').toString();
	}

	private static void field(StringBuilder b, String name, Object value) {
		if (b.length() > 1) {
			b.append(',');
		}
		string(b, name);
		b.append(':');
		if (value == null) {
			b.append("null");
		} else if (value instanceof Number || value instanceof Boolean) {
			b.append(value);
		} else if (value instanceof List) {
			b.append('[');
			boolean first = true;
			for (Object o : (List<?>) value) {
				if (!first) {
					b.append(',');
				}
				first = false;
				string(b, String.valueOf(o));
			}
			b.append(']');
		} else {
			string(b, value.toString());
		}
	}

	private static void string(StringBuilder b, String s) {
		b.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
			case '"':
				b.append("\\\"");
				break;
			case '\\':
				b.append("\\\\");
				break;
			case '\n':
				b.append("\\n");
				break;
			case '\r':
				b.append("\\r");
				break;
			case '\t':
				b.append("\\t");
				break;
			default:
				if (c < 0x20 || c == 0x2028 || c == 0x2029) {
					b.append(String.format("\\u%04x", (int) c));
				} else {
					b.append(c);
				}
			}
		}
		b.append('"');
	}
}
