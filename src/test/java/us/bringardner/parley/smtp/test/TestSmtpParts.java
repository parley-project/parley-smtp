package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.smtp.MailAddress;
import us.bringardner.parley.smtp.MailPath;
import us.bringardner.parley.smtp.SmtpInput;
import us.bringardner.parley.smtp.SmtpStreams;

/** Addresses, paths, parameters and the DATA encoding. */
public class TestSmtpParts {

	@Test
	public void testAddresses() {
		MailAddress a = MailAddress.parse("Tony.B@Example.COM", false);
		assertEquals("Tony.B", a.getLocalPart());
		assertEquals("example.com", a.getAsciiDomain());
		assertEquals(a, MailAddress.parse("Tony.B@example.com", false), "domains compare without case");
		assertFalse(a.equals(MailAddress.parse("tony.b@example.com", false)), "local parts are case-sensitive");
		assertEquals("\"a b\"@example.com", MailAddress.parse("\"a b\"@example.com", false).toString());
		assertEquals("user@[192.0.2.1]", MailAddress.parse("user@[192.0.2.1]", false).toString());
		assertTrue(MailAddress.parse("user@[IPv6:2001:db8::1]", false).isAddressLiteral());
		assertThrows(IllegalArgumentException.class, () -> MailAddress.parse("user@[300.1.1.1]", false));
		assertThrows(IllegalArgumentException.class, () -> MailAddress.parse("a..b@example.com", false));
		assertThrows(IllegalArgumentException.class, () -> MailAddress.parse("user@-bad.com", false));
		assertThrows(IllegalArgumentException.class, () -> MailAddress.parse("nodomain", false));
		assertThrows(IllegalArgumentException.class, () -> MailAddress.parse("josé@example.com", false), "needs SMTPUTF8");
		MailAddress u = MailAddress.parse("josé@bücher.example", true);
		assertTrue(u.needsSmtpUtf8());
		assertEquals("xn--bcher-kva.example", u.getAsciiDomain());
		assertFalse(MailAddress.parse("tony@bücher.example", true).needsSmtpUtf8(), "a U-label domain can be sent as A-labels");
	}

	@Test
	public void testPaths() {
		MailPath p = MailPath.parse("<tony@example.com> SIZE=1000 BODY=8BITMIME smtputf8", true, true, false);
		assertEquals("tony@example.com", p.getAddress().toString());
		assertEquals("1000", p.getParameters().get("SIZE"));
		assertEquals("8BITMIME", p.getParameters().get("BODY"));
		assertEquals("", p.getParameters().get("SMTPUTF8"));
		assertNull(MailPath.parse("<>", true, false, false).getAddress());
		assertThrows(IllegalArgumentException.class, () -> MailPath.parse("<>", false, false, false));
		assertEquals("b@c.d", MailPath.parse("<@a.example,@b.example:b@c.d>", false, false, false).getAddress().toString(),
				"a source route is ignored");
		assertEquals("x@y.z", MailPath.parse(" x@y.z", false, false, true).getAddress().toString(), "lenient: no brackets");
		assertThrows(IllegalArgumentException.class, () -> MailPath.parse("x@y.z", false, false, false));
		assertThrows(IllegalArgumentException.class, () -> MailPath.parse("<x@y.z> SIZE=1 SIZE=2", false, false, false));
		assertThrows(IllegalArgumentException.class, () -> MailPath.parse("<x@y.z>SIZE=1", false, false, false));
		assertEquals("\"a>b\"@y.z", MailPath.parse("<\"a>b\"@y.z>", false, false, false).getAddress().toString());
	}

	@Test
	public void testXtext() {
		assertEquals("a+b=c d", MailPath.decodeXtext("a+2Bb+3Dc+20d"));
		assertEquals("a+2Bb+3Dc+20d", MailPath.encodeXtext("a+b=c d"));
		assertThrows(IllegalArgumentException.class, () -> MailPath.decodeXtext("bad+2"));
	}

	private static String readData(String wire, long max) throws IOException {
		SmtpInput in = new SmtpInput(new ByteArrayInputStream(wire.getBytes(StandardCharsets.ISO_8859_1)));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SmtpInput.DataResult r = in.readData(out, max);
		return (r.tooLarge ? "TOO LARGE " : "") + out.toString(StandardCharsets.ISO_8859_1) + "|" + r.size;
	}

	@Test
	public void testReadData() throws IOException {
		assertEquals("a\r\n.b\r\n|7", readData("a\r\n..b\r\n.\r\nNEXT", 100));
		assertEquals("|0", readData(".\r\n", 100), "empty content");
		assertEquals(".x\r\n|4", readData("..x\r\n.\r\n", 100));
		assertEquals("a\n.\nb\r\n|7", readData("a\n.\nb\r\n.\r\n", 100), "a dot after a bare LF is content");
		assertEquals("a\r\n|3", readData("a\r\n.\r\nb\r\n.\r\n", 100), "ends at the first CRLF.CRLF");
		assertTrue(readData("0123456789\r\n.\r\n", 5).startsWith("TOO LARGE 01234"));
		assertThrows(java.io.EOFException.class, () -> readData("no end\r\n", 100));
	}

	@Test
	public void testDotStuffing() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SmtpStreams.DotStuffingOutputStream d = new SmtpStreams.DotStuffingOutputStream(out);
		d.write(".start\n.\nend".getBytes(StandardCharsets.US_ASCII));
		d.finish();
		assertEquals("..start\r\n..\r\nend\r\n.\r\n", out.toString(StandardCharsets.US_ASCII));
		// round trip through the reader
		SmtpInput in = new SmtpInput(new ByteArrayInputStream(out.toByteArray()));
		ByteArrayOutputStream back = new ByteArrayOutputStream();
		in.readData(back, 1000);
		assertEquals(".start\r\n.\r\nend\r\n", back.toString(StandardCharsets.US_ASCII));
	}
}
