package us.bringardner.parley.smtp.queue;

import us.bringardner.parley.io.IoUtils;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Predicate;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.smtp.dkim.HeaderFields;

/**
 * Adds header fields to (and removes some from) a message file without
 * reading its body into memory: the file is copied to a temporary file,
 * which then replaces it.
 */
public final class HeaderRewriter {

	private HeaderRewriter() {
	}

	/** Put {@code fields} (complete fields ending in CRLF) at the top of the message. */
	public static void prepend(FileSource file, FileSource tmp, String fields) throws IOException {
		try {
			copyWithPrefix(file, tmp, fields);
		} catch (IOException | RuntimeException e) {
			tmp.delete();
			throw e;
		}
		replace(file, tmp);
	}

	private static void copyWithPrefix(FileSource file, FileSource tmp, String fields) throws IOException {
		try (InputStream i = IoUtils.buffered(file.getInputStream());
				OutputStream o = IoUtils.buffered(tmp.getOutputStream())) {
			o.write(fields.getBytes(StandardCharsets.UTF_8));
			i.transferTo(o);
		}
	}

	/**
	 * Insert {@code fields} after the first header field (a trace field such
	 * as our Received) and leave out the fields {@code drop} matches.
	 */
	public static void insertAfterFirst(FileSource file, FileSource tmp, String fields, Predicate<HeaderFields.Field> drop)
			throws IOException {
		try {
			copyInserting(file, tmp, fields, drop);
		} catch (IOException | RuntimeException e) {
			tmp.delete();
			throw e;
		}
		replace(file, tmp);
	}

	private static void copyInserting(FileSource file, FileSource tmp, String fields, Predicate<HeaderFields.Field> drop)
			throws IOException {
		try (InputStream i = IoUtils.buffered(file.getInputStream());
				OutputStream o = IoUtils.buffered(tmp.getOutputStream())) {
			HeaderFields h = HeaderFields.read(i);
			List<HeaderFields.Field> all = h.getFields();
			boolean inserted = false;
			for (int n = 0; n < all.size(); n++) {
				HeaderFields.Field f = all.get(n);
				if (n > 0 && drop != null && drop.test(f)) {
					continue;
				}
				o.write(f.getRaw().getBytes(StandardCharsets.ISO_8859_1));
				if (n == 0) {
					o.write(fields.getBytes(StandardCharsets.UTF_8));
					inserted = true;
				}
			}
			if (!inserted) {
				o.write(fields.getBytes(StandardCharsets.UTF_8));
			}
			if (h.hasBody()) {
				o.write('\r');
				o.write('\n');
			}
			i.transferTo(o);
		}
	}

	private static void replace(FileSource file, FileSource tmp) throws IOException {
		file.delete();
		if (!tmp.renameTo(file)) {
			throw new IOException("Can't store the message");
		}
	}
}
