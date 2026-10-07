package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * Relay networks (clients that may relay without AUTH) use parley-core's AddressMatcher.
 * Before, a negative prefix ("10.0.0.0/-1") matched every IPv4 client, an open relay; a
 * prefix too long for the address failed at the first check; and a host name was looked up.
 */
public class TestRelayNetworks {

	private static InetAddress ip(String s) throws Exception {
		return InetAddress.getByName(s);
	}

	@Test
	public void testRelayNetworks() throws Exception {
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		assertFalse(s.isRelayAllowed(ip("127.0.0.1")), "Nobody relays by default");

		s.addRelayNetwork("127.0.0.0/8");
		s.addRelayNetwork("10.1.0.0/16, ::1");
		assertTrue(s.isRelayAllowed(ip("127.0.0.1")));
		assertTrue(s.isRelayAllowed(ip("10.1.200.3")));
		assertTrue(s.isRelayAllowed(ip("::1")));
		assertFalse(s.isRelayAllowed(ip("10.2.0.1")));
		assertFalse(s.isRelayAllowed(ip("203.0.113.5")));
		assertFalse(s.isRelayAllowed(null));
	}

	@Test
	public void testBadNetworksAreRejected() throws Exception {
		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		for(String bad : new String[] {"10.0.0.0/-1", "10.0.0.0/33", "2001:db8::/129", "mail.example.com", "1.2.3.999"}) {
			assertThrows(IllegalArgumentException.class, () -> s.addRelayNetwork(bad), bad);
		}
		assertFalse(s.isRelayAllowed(ip("203.0.113.5")), "A rejected network must not open the relay");
	}
}
