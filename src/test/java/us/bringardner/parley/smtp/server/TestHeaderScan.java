package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.junit.jupiter.api.Test;

/**
 * The block-at-a-time header scan and trace insertion must give what the
 * original byte-at-a-time versions gave, whatever the block boundaries do.
 */
public class TestHeaderScan {

	/** The scan as it was: a byte at a time, lower-casing every line. */
	private static SmtpRequestProcessor.HeaderScan reference(byte[] msg) throws IOException {
		SmtpRequestProcessor.HeaderScan s = new SmtpRequestProcessor.HeaderScan();
		try (InputStream in = new ByteArrayInputStream(msg)) {
			StringBuilder line = new StringBuilder();
			long total = 0;
			int b;
			while ((b = in.read()) >= 0 && total++ < 4 * 1024 * 1024) {
				if (b == '\n') {
					if (line.toString().trim().isEmpty()) {
						break;
					}
					String lower = line.toString().toLowerCase(Locale.ROOT);
					if (lower.startsWith("received:")) {
						s.received++;
					} else if (lower.startsWith("date:")) {
						s.date = true;
					} else if (lower.startsWith("message-id:")) {
						s.messageId = true;
					}
					line.setLength(0);
				} else if (line.length() < 64) {
					line.append((char) b);
				}
			}
		}
		return s;
	}

	private static byte[] bytes(String s) {
		return s.getBytes(StandardCharsets.ISO_8859_1);
	}

	private static void same(String msg) throws IOException {
		byte[] m = bytes(msg);
		SmtpRequestProcessor.HeaderScan want = reference(m);
		SmtpRequestProcessor.HeaderScan got = SmtpRequestProcessor.HeaderScan.of(new ByteArrayInputStream(m));
		assertEquals(want.received, got.received, "received in " + msg);
		assertEquals(want.date, got.date, "date in " + msg);
		assertEquals(want.messageId, got.messageId, "message-id in " + msg);
	}

	@Test
	public void sameAsTheByteScan() throws IOException {
		String[] msgs = {
				"",
				"\r\n",
				"Subject: x\r\n\r\nbody",
				"Received: a\r\nReceived: b\r\nDate: d\r\nMessage-ID: <1@x>\r\n\r\nbody Received: z\r\n",
				"RECEIVED: a\r\nDATE: d\r\nmessage-id: <1@x>\r\n\r\n",
				"Received: a\r\n by x\r\n\twith y\r\nDate: d\r\n\r\n",
				" Received: indented\r\nX-Received: no\r\nReceivedx: no\r\n\r\n",
				"Received: a\nReceived: b\n\nDate: after the blank line\n",
				"Subject: x\r\n \r\nDate: after a white space only line\r\n",
				"Received: a\r\nDate: d",		// no final line end: not counted
				"Message-ID:<1@x>\r\n\r\n",
				"Date:\r\n\r\n",
				"éÿ: binary\r\nReceived: a\r\n\r\n",
				"Recei",
		};
		for(String m : msgs) {
			same(m);
		}
	}

	@Test
	public void sameWhenTheBlockBoundaryFallsInsideAField() throws IOException {
		// push the interesting lines across the 8192 byte block boundary at every offset
		for(int pad = 8170; pad < 8200; pad++) {
			StringBuilder sb = new StringBuilder("X-Pad: ");
			for(int i = 0; i < pad; i++) {
				sb.append('p');
			}
			sb.append("\r\nReceived: a\r\nDate: d\r\nMessage-ID: <1@x>\r\n\r\nReceived: body\r\n");
			same(sb.toString());
		}
	}

	@Test
	public void longHeaderLinesAndLongBlocks() throws IOException {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < 3000; i++) {
			sb.append("Received: from host").append(i).append(" by mx with ESMTP id ").append(i).append("\r\n");
		}
		sb.append("\r\nbody");
		same(sb.toString());
		same("Subject: " + "s".repeat(1000) + "\r\nDate: d\r\n\r\n");
	}

	private static byte[] insert(byte[] msg, String add) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SmtpRequestProcessor.copyInsertingAfterTrace(new ByteArrayInputStream(msg), out, bytes(add));
		return out.toByteArray();
	}

	@Test
	public void insertsAfterTheFirstField() throws IOException {
		String add = "Date: d\r\n";
		assertEquals("Received: a\r\n by x\r\n" + add + "Subject: s\r\n\r\nbody",
				new String(insert(bytes("Received: a\r\n by x\r\nSubject: s\r\n\r\nbody"), add), StandardCharsets.ISO_8859_1));
		// no second field: appended
		assertEquals("Received: a\r\n" + add, new String(insert(bytes("Received: a\r\n"), add), StandardCharsets.ISO_8859_1));
		assertEquals(add, new String(insert(new byte[0], add), StandardCharsets.ISO_8859_1));
	}

	@Test
	public void insertsWhateverTheBlockBoundary() throws IOException {
		String add = "Message-ID: <1@x>\r\n";
		for(int pad = 8170; pad < 8200; pad++) {
			String first = "Received: " + "r".repeat(pad) + "\r\n";
			String rest = "Subject: s\r\n\r\n" + "b".repeat(20000);
			assertArrayEquals(bytes(first + add + rest), insert(bytes(first + rest), add), "pad " + pad);
		}
	}

	@Test
	public void timing() throws IOException {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < 20; i++) {
			sb.append("Received: from host").append(i).append(" by mx.example.com with ESMTPS id ").append(i).append("\r\n");
		}
		sb.append("Date: d\r\nMessage-ID: <1@x>\r\nSubject: s\r\n\r\n").append("b".repeat(50000));
		byte[] m = bytes(sb.toString());
		int n = 20000;
		for(int i = 0; i < 2000; i++) {
			reference(m);
			SmtpRequestProcessor.HeaderScan.of(new ByteArrayInputStream(m));
		}
		long t0 = System.nanoTime();
		for(int i = 0; i < n; i++) {
			reference(m);
		}
		long old = System.nanoTime() - t0;
		t0 = System.nanoTime();
		for(int i = 0; i < n; i++) {
			SmtpRequestProcessor.HeaderScan.of(new ByteArrayInputStream(m));
		}
		long now = System.nanoTime() - t0;
		System.out.printf("[header scan] %d scans: byte-at-a-time %.0f ms, block scan %.0f ms (%.1fx)%n",
				n, old/1e6, now/1e6, (double) old / now);
	}
}
