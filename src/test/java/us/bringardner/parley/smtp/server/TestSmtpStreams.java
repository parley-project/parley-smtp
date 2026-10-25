package us.bringardner.parley.smtp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.smtp.SmtpStreams;

/** CrlfOutputStream gives the same output however the content is split into writes. */
public class TestSmtpStreams {

	private static String text(ByteArrayOutputStream b) {
		return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
	}

	@Test
	public void lineEndsBecomeCrlf() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SmtpStreams.CrlfOutputStream c = new SmtpStreams.CrlfOutputStream(out);
		byte[] b = "a\nb\r\nc\rd\r".getBytes(StandardCharsets.ISO_8859_1);
		c.write(b, 0, b.length);
		c.finish();
		assertEquals("a\r\nb\r\nc\r\nd\r\n", text(out));
	}

	@Test
	public void blocksAndSingleBytesGiveTheSameOutput() throws IOException {
		Random r = new Random(7);
		byte[] alphabet = {'a', 'b', '.', '\r', '\n', ' '};
		for (int round = 0; round < 500; round++) {
			byte[] content = new byte[r.nextInt(200)];
			for (int k = 0; k < content.length; k++) {
				content[k] = alphabet[r.nextInt(alphabet.length)];
			}
			ByteArrayOutputStream one = new ByteArrayOutputStream();
			SmtpStreams.CrlfOutputStream a = new SmtpStreams.CrlfOutputStream(one);
			for (byte x : content) {
				a.write(x);
			}
			a.finish();
			ByteArrayOutputStream blocks = new ByteArrayOutputStream();
			SmtpStreams.CrlfOutputStream b = new SmtpStreams.CrlfOutputStream(blocks);
			int at = 0;
			while (at < content.length) {
				int n = Math.min(content.length - at, 1 + r.nextInt(20));
				b.write(content, at, n);
				at += n;
			}
			b.finish();
			assertEquals(text(one), text(blocks));
		}
	}
}
