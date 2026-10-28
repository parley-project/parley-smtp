package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimResult;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.queue.DeliveryConfig;

/**
 * The shared DKIM key (the queue's dkim.shared): mail from a local domain without a key of its own
 * is signed with the shared domain's key and selector as that local domain, and verifies where that
 * domain publishes the same public key (as an inherited record in Parley DNS); a domain's own key
 * still wins, and other domains aren't signed.
 */
public class TestSharedDkimKey {

	private static String message(String from) {
		return "From: someone@" + from + "\r\nTo: x@far.test\r\nSubject: hi\r\nDate: Wed, 28 Oct 2026 10:00:00 -0400\r\n"
				+ "Message-ID: <1@" + from + ">\r\n\r\nHello\r\n";
	}

	private static DkimResult signAndVerify(DkimSigner signer, String from, Map<String, String> dns) throws Exception {
		String msg = message(from);
		String field = signer.sign(new ByteArrayInputStream(msg.getBytes(StandardCharsets.US_ASCII)));
		DeliveryConfig v = new DeliveryConfig();
		v.getDkim().setLookup(TestDkim.keys(dns));
		List<DkimResult> r = v.getDkim().verify(new ByteArrayInputStream((field + msg).getBytes(StandardCharsets.US_ASCII)));
		assertEquals(1, r.size(), r.toString());
		return r.get(0);
	}

	@Test
	public void localDomainsWithoutAKeySignWithTheSharedOne() throws Exception {
		KeyPair primary = DkimKeys.generate("rsa");
		KeyPair own = DkimKeys.generate("rsa");
		DeliveryConfig c = new DeliveryConfig();
		c.setLocalDomains(Arrays.asList("primary.test", "other.test", "sub.third.test", "own.test"));
		c.getDkim().setSigners(Arrays.asList(new DkimSigner("primary.test", "mx1", primary.getPrivate()),
				new DkimSigner("own.test", "s2026", own.getPrivate())));

		// no shared key: only the domains with keys are signed
		assertNull(c.dkimSignerFor("other.test"));
		assertEquals("primary.test", c.dkimSignerFor("primary.test").getDomain());

		c.getDkim().setShared("primary.test");
		DkimSigner other = c.dkimSignerFor("other.test");
		assertEquals("other.test", other.getDomain(), "signs as the local domain (DMARC alignment)");
		assertEquals("mx1", other.getSelector());
		assertSame(other, c.dkimSignerFor("OTHER.test"), "made once per domain");
		assertEquals("other.test", c.dkimSignerFor("news.other.test").getDomain(), "a subdomain signs as its local domain");
		assertEquals("sub.third.test", c.dkimSignerFor("sub.third.test").getDomain());
		assertNull(c.dkimSignerFor("third.test"), "not a local domain (only its subdomain is)");
		assertNull(c.dkimSignerFor("far.test"), "not a local domain");
		assertNull(c.dkimSignerFor(null));
		assertEquals("primary.test", c.dkimSignerFor("primary.test").getDomain());
		assertEquals("s2026", c.dkimSignerFor("own.test").getSelector(), "a domain's own key wins");

		// verifies where the domain publishes the primary's public key under the same selector (inherited in Parley DNS)
		Map<String, String> dns = new HashMap<>();
		dns.put("mx1._domainkey.other.test", DkimKeys.dnsRecord(primary.getPublic()));
		DkimResult r = signAndVerify(other, "other.test", dns);
		assertTrue(r.isPass(), r.toString());
		assertEquals("other.test", r.getDomain());
		// and not where it doesn't
		assertTrue(!signAndVerify(other, "other.test", new HashMap<>()).isPass());

		// a key for the shared domain that isn't there: nothing is signed with it
		c.getDkim().setShared("missing.test");
		assertNull(c.dkimSignerFor("other.test"));
		c.getDkim().setShared(null);
		assertNull(c.dkimSignerFor("other.test"));
	}
}
