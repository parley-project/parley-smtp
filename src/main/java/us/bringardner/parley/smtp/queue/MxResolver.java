package us.bringardner.parley.smtp.queue;

import java.util.List;


/** Finds the servers that receive mail for a domain (RFC 5321 section 5.1). */
public interface MxResolver {

	/** A server to try: host name or address, and port. */
	final class Route {
		/** The host name (used for TLS server name checks and in messages). */
		public final String host;
		/** The address to connect to, or null to look the host name up when connecting. */
		public final java.net.InetAddress address;
		public final int port;

		public Route(String host, int port) {
			this(host, null, port);
		}

		public Route(String host, java.net.InetAddress address, int port) {
			this.host = host;
			this.address = address;
			this.port = port;
		}

		@Override
		public String toString() {
			return host + (address == null ? "" : "[" + address.getHostAddress() + "]") + ":" + port;
		}
	}

	/**
	 * The servers for a domain (A-labels, lower case), most preferred first.
	 *
	 * @throws DeliveryException permanent if the domain doesn't exist or accepts no
	 *                           mail (null MX), temporary if DNS failed
	 */
	List<Route> resolve(String domain, int port) throws DeliveryException;
}
