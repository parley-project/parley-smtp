package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Txt;
import us.bringardner.parley.dns.resolve.Lookup;
import us.bringardner.parley.smtp.dkim.Canonicalization;
import us.bringardner.parley.smtp.dkim.DkimKeyLookup;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.DkimResult.Result;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dkim.DkimVerifier;
import us.bringardner.parley.smtp.dkim.HeaderFields;

/** DKIM signing and verification, checked against the RFC 8463 appendix A example. */
public class TestDkim {

	// ------------------------------------------------------------------ RFC 8463 appendix A

	static final String ED25519_SECRET = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

	static final String RSA_SECRET = "-----BEGIN RSA PRIVATE KEY-----\n"
			+ "MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi\n"
			+ "Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM\n"
			+ "KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB\n"
			+ "AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm\n"
			+ "6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe\n"
			+ "zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy\n"
			+ "6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc\n"
			+ "uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy\n"
			+ "WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd\n"
			+ "WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a\n"
			+ "licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst\n"
			+ "o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe\n"
			+ "uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL\n"
			+ "-----END RSA PRIVATE KEY-----\n";

	static final String ED25519_RECORD = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

	static final String RSA_RECORD = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR"
			+ "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC"
			+ "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" + "Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

	static final String SIGNED = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n"
			+ " d=football.example.com; i=@football.example.com;\r\n"
			+ " q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n"
			+ " subject : date : message-id : from : subject : date;\r\n"
			+ " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
			+ " b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n"
			+ " Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n"
			+ "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
			+ " d=football.example.com; i=@football.example.com;\r\n"
			+ " q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n"
			+ " date : message-id : from : subject : date;\r\n"
			+ " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
			+ " b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n"
			+ " DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n"
			+ " dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n";

	static final String MESSAGE = "From: Joe SixPack <joe@football.example.com>\r\n"
			+ "To: Suzie Q <suzie@shopping.example.net>\r\n"
			+ "Subject: Is dinner ready?\r\n"
			+ "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
			+ "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"
			+ "\r\n"
			+ "Hi.\r\n"
			+ "\r\n"
			+ "We lost the game.  Are you hungry yet?\r\n"
			+ "\r\n"
			+ "Joe.\r\n"
			+ "\r\n";

	// ------------------------------------------------------------------ helpers

	/** Key lookups from a map; names not in it are NXDOMAIN, "TEMPFAIL" values time out. */
	static DkimKeyLookup keys(Map<String, String> records) {
		return name -> {
			String rec = records.get(name.toLowerCase());
			if ("TEMPFAIL".equals(rec)) {
				return Lookup.txt(name, null);
			}
			Message m = new Message();
			m.setQuestion(name, DNS.TXT, DNS.IN);
			m.setMessageTypeResponse();
			if (rec == null) {
				m.setResponseCode(DNS.NAME_ERROR);
			} else {
				Txt t = new Txt(name);
				t.setText(rec);
				t.setTTL(300);
				m.addAnswer(t);
			}
			return Lookup.txt(name, m);
		};
	}

	static Map<String, String> rfcKeys() {
		Map<String, String> m = new HashMap<>();
		m.put("brisbane._domainkey.football.example.com", ED25519_RECORD);
		m.put("test._domainkey.football.example.com", RSA_RECORD);
		return m;
	}

	static List<DkimResult> verify(DkimKeyLookup lookup, String message) throws Exception {
		return new DkimVerifier(lookup).verify(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
	}

	static boolean ed25519() {
		try {
			KeyFactory.getInstance("Ed25519");
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	static String b64(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	// ------------------------------------------------------------------ verification

	@Test
	public void rfc8463ExampleVerifies() throws Exception {
		List<DkimResult> r = verify(keys(rfcKeys()), SIGNED + MESSAGE);
		assertEquals(2, r.size());
		DkimResult rsa = r.get(1);
		assertEquals(Result.PASS, rsa.getResult(), rsa.toString());
		assertEquals("football.example.com", rsa.getDomain());
		assertEquals("test", rsa.getSelector());
		assertEquals("dkim=pass header.d=football.example.com header.i=@football.example.com header.s=test"
				+ " header.a=rsa-sha256 header.b=F45dVWDf", rsa.toAuthResults());
		if (ed25519()) {
			assertEquals(Result.PASS, r.get(0).getResult(), r.get(0).toString());
		} else {
			assertEquals(Result.PERMERROR, r.get(0).getResult());
		}
	}

	@Test
	public void changedBodyFails() throws Exception {
		List<DkimResult> r = verify(keys(rfcKeys()), SIGNED + MESSAGE.replace("hungry", "angry"));
		for (DkimResult d : r) {
			assertEquals(Result.FAIL, d.getResult());
			assertEquals("body hash did not verify", d.getReason());
		}
	}

	@Test
	public void changedHeaderFails() throws Exception {
		List<DkimResult> r = verify(keys(rfcKeys()), SIGNED + MESSAGE.replace("dinner", "lunch"));
		assertEquals(Result.FAIL, r.get(1).getResult());
		assertEquals("signature did not verify", r.get(1).getReason());
	}

	@Test
	public void addedFromFails() throws Exception {
		// From is over-signed, so a second From breaks the signature
		String m = SIGNED + "From: mallory@evil.example\r\n" + MESSAGE;
		assertEquals(Result.FAIL, verify(keys(rfcKeys()), m).get(1).getResult());
	}

	@Test
	public void whitespaceChangesPassRelaxed() throws Exception {
		String m = SIGNED + MESSAGE.replace("Subject: Is dinner ready?", "Subject:   Is  dinner\r\n\tready?  ")
				.replace("Joe.\r\n", "Joe.   \r\n\r\n\r\n");
		assertEquals(Result.PASS, verify(keys(rfcKeys()), m).get(1).getResult());
	}

	@Test
	public void keyProblems() throws Exception {
		Map<String, String> k = rfcKeys();
		k.remove("test._domainkey.football.example.com");
		assertEquals("no key for signature", verify(keys(k), SIGNED + MESSAGE).get(1).getReason());
		assertEquals(Result.PERMERROR, verify(keys(k), SIGNED + MESSAGE).get(1).getResult());

		k.put("test._domainkey.football.example.com", "TEMPFAIL");
		assertEquals(Result.TEMPERROR, verify(keys(k), SIGNED + MESSAGE).get(1).getResult());

		k.put("test._domainkey.football.example.com", "v=DKIM1; k=rsa; p=");
		assertEquals("key revoked", verify(keys(k), SIGNED + MESSAGE).get(1).getReason());

		k.put("test._domainkey.football.example.com", RSA_RECORD + "; s=voice");
		assertEquals("key is not for email", verify(keys(k), SIGNED + MESSAGE).get(1).getReason());

		k.put("test._domainkey.football.example.com", RSA_RECORD.replace("k=rsa", "k=ed25519"));
		assertEquals(Result.PERMERROR, verify(keys(k), SIGNED + MESSAGE).get(1).getResult());

		k.put("test._domainkey.football.example.com", RSA_RECORD + "; t=y");
		DkimResult testing = verify(keys(k), SIGNED + MESSAGE).get(1);
		assertEquals(Result.PASS, testing.getResult());
		assertTrue(testing.isTesting());
		assertTrue(testing.toAuthResults().contains("testing"));
	}

	@Test
	public void noSignature() throws Exception {
		List<DkimResult> r = verify(keys(rfcKeys()), MESSAGE);
		assertEquals(1, r.size());
		assertEquals(Result.NONE, r.get(0).getResult());
		assertEquals("dkim=none", r.get(0).toAuthResults());
	}

	@Test
	public void badSignatureFields() throws Exception {
		String rsa = SIGNED.substring(SIGNED.indexOf("DKIM-Signature: v=1; a=rsa"));
		String[][] cases = {
				{"a=rsa-sha256", "a=rsa-sha1", "rsa-sha1 signatures are not accepted (RFC 8301)"},
				{"v=1;", "v=2;", "unsupported version v=2"},
				{"h=from : to : subject :\r\n date : message-id : from : subject : date", "h=to : subject :\r\n date : message-id : subject : date", "From is not signed"},
				{"i=@football.example.com", "i=@other.example.com", "i= domain is not d= or a subdomain of it"},
				{"q=dns/txt", "q=http", "unsupported query method q=http"},
				{"t=1528637909;", "t=1528637909; x=1528637910;", "signature expired"},
				{"s=test;", "", "no s= tag"},
				{"s=test;", "s=test; s=test;", "duplicate tag s"},
		};
		for (String[] c : cases) {
			DkimResult r = verify(keys(rfcKeys()), rsa.replace(c[0], c[1]) + MESSAGE).get(0);
			assertEquals(Result.PERMERROR, r.getResult(), c[1]);
			assertEquals(c[2], r.getReason(), c[1]);
		}
	}

	@Test
	public void maxSignatures() throws Exception {
		DkimVerifier v = new DkimVerifier(keys(rfcKeys()));
		v.setMaxSignatures(1);
		String rsa = SIGNED.substring(SIGNED.indexOf("DKIM-Signature: v=1; a=rsa"));
		List<DkimResult> r = v.verify(new ByteArrayInputStream((rsa + SIGNED + MESSAGE).getBytes(StandardCharsets.UTF_8)));
		assertEquals(1, r.size());
		assertEquals(Result.PASS, r.get(0).getResult());
	}

	// ------------------------------------------------------------------ signing

	@Test
	public void signRsaAndVerify() throws Exception {
		DkimSigner s = new DkimSigner("football.example.com", "test", DkimKeys.privateKey(RSA_SECRET));
		assertEquals(DkimSigner.RSA_SHA256, s.getAlgorithm());
		String field = s.sign(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)), 1528637909);
		assertTrue(field.startsWith("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"), field);
		assertTrue(field.contains("d=football.example.com; s=test; t=1528637909;"), field);
		assertTrue(field.endsWith("\r\n"));
		for (String line : field.split("\r\n")) {
			assertTrue(line.length() <= 78, line);
		}
		// the same body hash as the RFC example
		assertTrue(field.contains("bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="), field);
		// each field present, then every over-signed name once more (absent ones too)
		assertTrue(field.contains("h=from:subject:date:message-id:to:from:sender:reply-to:subject:date:\r\n\tmessage-id:to:cc:"), field);
		List<DkimResult> r = verify(keys(rfcKeys()), field + MESSAGE);
		assertEquals(Result.PASS, r.get(0).getResult(), r.toString());

		// deterministic: RSA PKCS#1 v1.5 gives the same signature again
		assertEquals(field, s.sign(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)), 1528637909));
	}

	@Test
	public void signEd25519AndVerify() throws Exception {
		assumeTrue(ed25519(), "Ed25519 needs Java 15");
		DkimSigner s = new DkimSigner("football.example.com", "brisbane", DkimKeys.privateKey(ED25519_SECRET));
		assertEquals(DkimSigner.ED25519_SHA256, s.getAlgorithm());
		String field = s.sign(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)));
		List<DkimResult> r = verify(keys(rfcKeys()), field + MESSAGE);
		assertEquals(Result.PASS, r.get(0).getResult(), r.toString());
	}

	@Test
	public void signSimpleAndVerify() throws Exception {
		DkimSigner s = new DkimSigner("football.example.com", "test", DkimKeys.privateKey(RSA_SECRET));
		s.setCanonicalization(Canonicalization.SIMPLE, Canonicalization.SIMPLE);
		s.setIdentity("joe@football.example.com");
		s.setExpireSeconds(3600);
		String field = s.sign(new ByteArrayInputStream(MESSAGE.getBytes(StandardCharsets.UTF_8)));
		assertTrue(field.contains("c=simple/simple;"));
		assertTrue(field.contains("x="));
		DkimResult r = verify(keys(rfcKeys()), field + MESSAGE).get(0);
		assertEquals(Result.PASS, r.getResult(), r.toString());
		assertEquals("joe@football.example.com", r.getIdentity());
		// simple: white space matters
		assertEquals(Result.FAIL, verify(keys(rfcKeys()), field + MESSAGE.replace("Subject: Is", "Subject:  Is")).get(0).getResult());
	}

	@Test
	public void manyHeadersFoldAndVerify() throws Exception {
		DkimSigner s = new DkimSigner("football.example.com", "test", DkimKeys.privateKey(RSA_SECRET));
		StringBuilder m = new StringBuilder();
		for (int i = 0; i < 20; i++) {
			m.append("Resent-To: r").append(i).append("@example.net\r\n");
		}
		m.append(MESSAGE);
		String field = s.sign(new ByteArrayInputStream(m.toString().getBytes(StandardCharsets.UTF_8)));
		for (String line : field.split("\r\n")) {
			assertTrue(line.length() <= 78, line);
		}
		assertEquals(Result.PASS, verify(keys(rfcKeys()), field + m).get(0).getResult());
	}

	@Test
	public void bodyLengthTag() throws Exception {
		// a hand-made l= signature: content after the first l octets may change
		String rsa = SIGNED.substring(SIGNED.indexOf("DKIM-Signature: v=1; a=rsa"));
		String withL = rsa.replace("t=1528637909;", "t=1528637909; l=100000;");
		DkimResult r = verify(keys(rfcKeys()), withL + MESSAGE).get(0);
		assertEquals(Result.PERMERROR, r.getResult());
		assertEquals("l= is longer than the body", r.getReason());
	}

	@Test
	public void signerChecks() throws Exception {
		PrivateKey k = DkimKeys.privateKey(RSA_SECRET);
		assertThrows(IllegalArgumentException.class, () -> new DkimSigner("bad domain", "s", k));
		assertThrows(IllegalArgumentException.class, () -> new DkimSigner("example.com", "bad selector", k));
		DkimSigner s = new DkimSigner("Example.COM.", "s1", k);
		assertEquals("example.com", s.getDomain());
		assertThrows(IllegalArgumentException.class, () -> s.setHeaders(Arrays.asList("subject")));
		assertThrows(java.security.GeneralSecurityException.class,
				() -> s.sign(new ByteArrayInputStream("Subject: x\r\n\r\nbody\r\n".getBytes(StandardCharsets.UTF_8))));
	}

	// ------------------------------------------------------------------ keys

	@Test
	public void keyFormats() throws Exception {
		KeyPair rsa = DkimKeys.generate("rsa");
		PrivateKey back = DkimKeys.privateKey(DkimKeys.toPem(rsa.getPrivate()));
		assertEquals(rsa.getPrivate(), back);
		String rec = DkimKeys.dnsRecord(rsa.getPublic());
		assertTrue(rec.startsWith("v=DKIM1; k=rsa; p=MIIBIj"), rec);

		// a generated key signs and verifies through its DNS record
		DkimSigner s = new DkimSigner("example.com", "k1", back);
		String msg = "From: a@example.com\r\nSubject: hi\r\n\r\nhello\r\n";
		String field = s.sign(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)));
		Map<String, String> m = new HashMap<>();
		m.put("k1._domainkey.example.com", rec);
		assertEquals(Result.PASS, verify(keys(m), field + msg).get(0).getResult());

		if (ed25519()) {
			KeyPair ed = DkimKeys.generate("ed25519");
			assertEquals(ed.getPrivate(), DkimKeys.privateKey(DkimKeys.toPem(ed.getPrivate())));
			// RFC 8463: the public key of the example secret key
			assertTrue(ED25519_RECORD.endsWith(DkimKeys.dnsRecord(
					java.security.KeyFactory.getInstance("Ed25519").generatePublic(new java.security.spec.X509EncodedKeySpec(
							Base64.getDecoder().decode("MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")))).substring(30)));
		}
		assertThrows(java.security.GeneralSecurityException.class,
				() -> DkimKeys.privateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"));
	}

	// ------------------------------------------------------------------ canonicalization

	@Test
	public void rfc6376CanonicalizationExample() throws Exception {
		// RFC 6376 section 3.4.6
		assertEquals("a:X\r\n", Canonicalization.RELAXED.header("A: X\r\n"));
		assertEquals("b:Y Z\r\n", Canonicalization.RELAXED.header("B : Y\t\r\n\tZ  \r\n"));
		assertEquals("B : Y\t\r\n\tZ  \r\n", Canonicalization.SIMPLE.header("B : Y\t\r\n\tZ  \r\n"));
		String body = " C \r\nD \t E\r\n\r\n\r\n";
		assertEquals(sha256(" C\r\nD E\r\n"), bodyHash(Canonicalization.RELAXED, body, -1));
		assertEquals(sha256(" C \r\nD \t E\r\n"), bodyHash(Canonicalization.SIMPLE, body, -1));
	}

	@Test
	public void bodyEdgeCases() throws Exception {
		assertEquals("frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", bodyHash(Canonicalization.SIMPLE, "", -1));
		assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", bodyHash(Canonicalization.RELAXED, "", -1));
		assertEquals(bodyHash(Canonicalization.SIMPLE, "", -1), bodyHash(Canonicalization.SIMPLE, "\r\n\r\n", -1));
		assertEquals(bodyHash(Canonicalization.RELAXED, "", -1), bodyHash(Canonicalization.RELAXED, " \t\r\n\r\n", -1));
		// a missing final CRLF is added
		assertEquals(sha256("abc\r\n"), bodyHash(Canonicalization.SIMPLE, "abc", -1));
		assertEquals(sha256("a b\r\n"), bodyHash(Canonicalization.RELAXED, "a \t b \t", -1));
		// a bare CR is content
		assertEquals(sha256("a\rb\r\n"), bodyHash(Canonicalization.SIMPLE, "a\rb\r\n", -1));
		// l=
		assertEquals(sha256("abc"), bodyHash(Canonicalization.SIMPLE, "abcdef\r\n", 3));
		// empty lines inside the body stay
		assertEquals(sha256("a\r\n\r\nb\r\n"), bodyHash(Canonicalization.RELAXED, "a\r\n \r\nb\r\n\r\n", -1));
	}

	static String bodyHash(Canonicalization c, String body, long limit) throws Exception {
		Canonicalization.BodyHasher h = c.bodyHasher(MessageDigest.getInstance("SHA-256"), limit);
		byte[] b = body.getBytes(StandardCharsets.ISO_8859_1);
		// written in odd pieces, to cross every state
		for (int i = 0; i < b.length; i += 3) {
			h.write(b, i, Math.min(3, b.length - i));
		}
		return b64(h.finish());
	}

	static String sha256(String s) throws Exception {
		return b64(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.ISO_8859_1)));
	}

	@Test
	public void largeBodyStreams() throws Exception {
		DkimSigner s = new DkimSigner("football.example.com", "test", DkimKeys.privateKey(RSA_SECRET));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(MESSAGE.getBytes(StandardCharsets.UTF_8));
		byte[] line = "0123456789 abcdefghijklmnopqrstuvwxyz \t ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n".getBytes(StandardCharsets.US_ASCII);
		for (int i = 0; i < 20000; i++) {
			out.write(line);
		}
		byte[] msg = out.toByteArray();
		String field = s.sign(new ByteArrayInputStream(msg));
		ByteArrayOutputStream signed = new ByteArrayOutputStream();
		signed.write(field.getBytes(StandardCharsets.US_ASCII));
		signed.write(msg);
		List<DkimResult> r = new DkimVerifier(keys(rfcKeys())).verify(new ByteArrayInputStream(signed.toByteArray()));
		assertEquals(Result.PASS, r.get(0).getResult());
	}

	// ------------------------------------------------------------------ header fields

	@Test
	public void addressDomains() {
		assertEquals("football.example.com", HeaderFields.addressDomain("Joe SixPack <joe@football.example.com>"));
		assertEquals("example.com", HeaderFields.addressDomain("joe@Example.COM"));
		assertEquals("example.com", HeaderFields.addressDomain("\"Joe <x@y.z>\" <joe@example.com>"));
		assertEquals("example.com", HeaderFields.addressDomain("joe@example.com (Joe @ home)"));
		assertEquals("a.example", HeaderFields.addressDomain("a@a.example, b@b.example"));
		assertEquals("example.com", HeaderFields.addressDomain("Team: joe@example.com, ann@example.com;"));
		assertEquals("xn--bcher-kva.example", HeaderFields.addressDomain("j@bücher.example"));
		assertNull(HeaderFields.addressDomain("undisclosed-recipients:;"));
		assertNull(HeaderFields.addressDomain(null));
	}

	@Test
	public void headerParsing() throws Exception {
		String m = "From: a@b.c\r\nSubject: one\r\n two\r\nX-Empty:\r\n\r\nbody";
		ByteArrayInputStream in = new ByteArrayInputStream(m.getBytes(StandardCharsets.UTF_8));
		HeaderFields h = HeaderFields.read(in);
		assertEquals(3, h.getFields().size());
		assertTrue(h.hasBody());
		assertEquals("Subject: one\r\n two\r\n", h.get("subject").getRaw());
		assertEquals("one two", h.get("SUBJECT").getValue());
		assertEquals("body", new String(in.readAllBytes(), StandardCharsets.UTF_8));

		HeaderFields only = HeaderFields.read(new ByteArrayInputStream("From: a@b.c\r\n".getBytes(StandardCharsets.UTF_8)));
		assertFalse(only.hasBody());
		assertEquals(1, only.getFields().size());

		List<String> names = new ArrayList<>();
		for (HeaderFields.Field f : HeaderFields.read(new ByteArrayInputStream("A : 1\r\nB:2\r\n\r\n".getBytes(StandardCharsets.UTF_8))).getFields()) {
			names.add(f.getName());
		}
		assertEquals(Arrays.asList("A", "B"), names);
	}
}
