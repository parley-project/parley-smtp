package us.bringardner.parley.smtp.dkim;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Reading and writing DKIM keys: private keys from PEM files, public keys from
 * DNS records (RFC 6376 section 3.6.1, RFC 8463), and the DNS record for a key.
 * <p>
 * Ed25519 uses the JDK's "Ed25519" algorithm, so it needs Java 15 or later at
 * run time; RSA works on Java 11.
 * <p>
 * Run {@code java us.bringardner.parley.smtp.dkim.DkimKeys rsa|ed25519 key.pem}
 * to make a key pair: the private key is written to the file and the TXT
 * record to publish is printed.
 */
public final class DkimKeys {

	/** The DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow. */
	private static final byte[] ED25519_SPKI_PREFIX = hex("302a300506032b6570032100");
	/** The DER prefix of an Ed25519 PKCS#8 private key; the 32-byte seed follows. */
	private static final byte[] ED25519_PKCS8_PREFIX = hex("302e020100300506032b657004220420");
	/** AlgorithmIdentifier rsaEncryption with NULL parameters. */
	private static final byte[] RSA_ALGORITHM_ID = hex("300d06092a864886f70d0101010500");

	private DkimKeys() {
	}

	/** Read a private key from a PEM file (see {@link #privateKey(String)}). */
	public static PrivateKey privateKey(File pemFile) throws IOException, GeneralSecurityException {
		return privateKey(new String(Files.readAllBytes(pemFile.toPath()), StandardCharsets.US_ASCII));
	}

	/**
	 * A private key from text: PEM "PRIVATE KEY" (PKCS#8, RSA or Ed25519),
	 * PEM "RSA PRIVATE KEY" (PKCS#1, as older openssl writes), or the base64 of
	 * a 32-byte Ed25519 secret key (as in RFC 8463 appendix A).
	 */
	public static PrivateKey privateKey(String text) throws GeneralSecurityException {
		String t = text.trim();
		byte[] der;
		boolean pkcs1 = t.contains("-----BEGIN RSA PRIVATE KEY-----");
		if (t.contains("-----BEGIN")) {
			if (t.contains("ENCRYPTED")) {
				throw new GeneralSecurityException("Encrypted private keys are not supported; write the key without a passphrase");
			}
			der = pemBody(t);
		} else {
			der = decode(t);
			if (der.length == 32) {
				return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(ED25519_PKCS8_PREFIX, der)));
			}
		}
		if (pkcs1) {
			// PrivateKeyInfo { version 0, rsaEncryption, OCTET STRING { RSAPrivateKey } }
			der = sequence(concat(hex("020100"), RSA_ALGORITHM_ID, tlv(0x04, der)));
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
		}
		GeneralSecurityException first = null;
		for (String alg : new String[] {"RSA", "Ed25519"}) {
			try {
				return KeyFactory.getInstance(alg).generatePrivate(new PKCS8EncodedKeySpec(der));
			} catch (GeneralSecurityException e) {
				if (first == null) {
					first = e;
				}
			}
		}
		throw new GeneralSecurityException("Not an RSA or Ed25519 private key", first);
	}

	/**
	 * The public key of a DNS key record's p= value.
	 *
	 * @param keyType the k= tag: "rsa" or "ed25519"
	 */
	static PublicKey publicKey(String keyType, byte[] p) throws DkimException {
		try {
			if (keyType.equals("ed25519")) {
				if (p.length != 32) {
					throw DkimException.perm("Ed25519 key is not 32 bytes");
				}
				return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI_PREFIX, p)));
			}
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey key;
			try {
				key = kf.generatePublic(new X509EncodedKeySpec(p));
			} catch (GeneralSecurityException e) {
				// a bare RSAPublicKey (PKCS#1), which some publish
				key = kf.generatePublic(new X509EncodedKeySpec(sequence(concat(RSA_ALGORITHM_ID, tlv(0x03, concat(new byte[1], p))))));
			}
			if (((RSAPublicKey) key).getModulus().bitLength() < 1024) {
				throw DkimException.perm("RSA key shorter than 1024 bits (RFC 8301)");
			}
			return key;
		} catch (NoSuchAlgorithmException e) {
			throw DkimException.perm(keyType + " keys are not supported by this Java (Ed25519 needs Java 15)");
		} catch (GeneralSecurityException | ClassCastException e) {
			throw DkimException.perm("invalid public key");
		}
	}

	/** The TXT record to publish at selector._domainkey.domain for a public key. */
	public static String dnsRecord(PublicKey key) {
		String alg = key.getAlgorithm();
		if (alg.equals("RSA")) {
			return "v=DKIM1; k=rsa; p=" + Base64.getEncoder().encodeToString(key.getEncoded());
		}
		if (alg.equals("EdDSA") || alg.equals("Ed25519")) {
			byte[] spki = key.getEncoded();
			return "v=DKIM1; k=ed25519; p=" + Base64.getEncoder().encodeToString(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
		}
		throw new IllegalArgumentException("Not an RSA or Ed25519 key: " + alg);
	}

	/** The key in PEM ("-----BEGIN PRIVATE KEY-----", PKCS#8). */
	public static String toPem(PrivateKey key) {
		String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(key.getEncoded());
		return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
	}

	/** Make a key pair: "rsa" (2048 bits) or "ed25519". */
	public static KeyPair generate(String type) throws GeneralSecurityException {
		if (type.equalsIgnoreCase("ed25519")) {
			return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
		}
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		return g.generateKeyPair();
	}

	/** Usage: DkimKeys rsa|ed25519 private-key.pem */
	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: java " + DkimKeys.class.getName() + " rsa|ed25519 private-key.pem");
			System.exit(2);
		}
		File f = new File(args[1]);
		if (f.exists()) {
			System.err.println(f + " already exists");
			System.exit(1);
		}
		KeyPair kp = generate(args[0]);
		try (OutputStream out = Files.newOutputStream(f.toPath())) {
			out.write(toPem(kp.getPrivate()).getBytes(StandardCharsets.US_ASCII));
		}
		f.setReadable(false, false);
		f.setReadable(true, true);
		System.out.println("Private key written to " + f);
		System.out.println("Publish this TXT record at <selector>._domainkey.<domain>:");
		System.out.println(dnsRecord(kp.getPublic()));
	}

	// ------------------------------------------------------------------ DER helpers

	private static byte[] pemBody(String pem) throws GeneralSecurityException {
		StringBuilder sb = new StringBuilder();
		boolean in = false;
		for (String line : pem.split("\\r?\\n")) {
			line = line.trim();
			if (line.startsWith("-----BEGIN")) {
				in = true;
			} else if (line.startsWith("-----END")) {
				break;
			} else if (in && !line.contains(":")) {
				sb.append(line);
			}
		}
		return decode(sb.toString());
	}

	private static byte[] decode(String b64) throws GeneralSecurityException {
		try {
			return Base64.getDecoder().decode(b64.replaceAll("\\s", ""));
		} catch (IllegalArgumentException e) {
			throw new GeneralSecurityException("Invalid base64 in the key", e);
		}
	}

	private static byte[] sequence(byte[] content) {
		return tlv(0x30, content);
	}

	private static byte[] tlv(int tag, byte[] content) {
		ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
		out.write(tag);
		int len = content.length;
		if (len < 0x80) {
			out.write(len);
		} else if (len < 0x100) {
			out.write(0x81);
			out.write(len);
		} else if (len < 0x10000) {
			out.write(0x82);
			out.write(len >> 8);
			out.write(len);
		} else {
			out.write(0x83);
			out.write(len >> 16);
			out.write(len >> 8);
			out.write(len);
		}
		out.write(content, 0, content.length);
		return out.toByteArray();
	}

	private static byte[] concat(byte[]... parts) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (byte[] p : parts) {
			out.write(p, 0, p.length);
		}
		return out.toByteArray();
	}

	private static byte[] hex(String s) {
		byte[] ret = new byte[s.length() / 2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return ret;
	}
}
