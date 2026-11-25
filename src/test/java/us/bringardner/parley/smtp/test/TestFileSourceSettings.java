package us.bringardner.parley.smtp.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;
import us.bringardner.parley.smtp.dkim.Dkim;
import us.bringardner.parley.smtp.dkim.DkimKeys;
import us.bringardner.parley.smtp.dkim.DkimSigner;
import us.bringardner.parley.smtp.dmarc.PublicSuffixList;
import us.bringardner.parley.smtp.server.SmtpServer;

/**
 * The files the SMTP server's settings name (DKIM keys, the aliases file, the public suffix list) are
 * read through FileSource, so each is a path on the file system the server uses or a
 * {@code filesource:} URL, and none has to be on the local disk.
 */
public class TestFileSourceSettings {

	/** The memory file systems a test made, disconnected after it */
	private final List<FileSourceFactory> made = new ArrayList<>();

	@AfterEach
	public void disconnect() throws IOException {
		for (FileSourceFactory f : made) {
			f.disConnect();
		}
		made.clear();
	}

	/** A new, empty memory file system */
	private FileSourceFactory memory() throws IOException {
		FileSourceFactory ret = new MemoryFileSourceFactory();
		ret.connect();
		made.add(ret);
		return ret;
	}

	private static FileSource write(FileSourceFactory factory, String path, String text) throws IOException {
		FileSource f = factory.createFileSource(path);
		f.getParentFile().mkdirs();
		try (OutputStream out = f.getOutputStream()) {
			out.write(text.getBytes(StandardCharsets.US_ASCII));
		}
		return f;
	}

	@Test
	public void aKeyIsReadFromAnyFileSource() throws Exception {
		KeyPair kp = DkimKeys.generate("rsa");
		FileSourceFactory fs = memory();
		FileSource f = write(fs, "/keys/a.pem", DkimKeys.toPem(kp.getPrivate()));
		assertArrayEquals(kp.getPrivate().getEncoded(), DkimKeys.privateKey(f).getEncoded());
	}

	@Test
	public void signersAreReadThroughTheFactoryGiven() throws Exception {
		KeyPair a = DkimKeys.generate("rsa");
		KeyPair b = DkimKeys.generate("ed25519");
		FileSourceFactory fs = memory();
		write(fs, "/keys/a.pem", DkimKeys.toPem(a.getPrivate()));
		write(fs, "/keys/b.pem", DkimKeys.toPem(b.getPrivate()));
		List<DkimSigner> signers = Dkim.parseSigners("a.test:s1:/keys/a.pem, b.test:s2:/keys/b.pem", null, fs);
		assertEquals(2, signers.size());
		assertEquals("a.test", signers.get(0).getDomain());
		assertEquals("s1", signers.get(0).getSelector());
		assertEquals("b.test", signers.get(1).getDomain());

		Dkim dkim = new Dkim();
		dkim.addSigners("a.test:s1:/keys/a.pem", null, fs);
		assertEquals(1, dkim.getSigners().size());
	}

	@Test
	public void aKeyThatIsNotOnThatFileSourceIsAnErrorAndNothingIsUsed() throws Exception {
		KeyPair a = DkimKeys.generate("rsa");
		FileSourceFactory fs = memory();
		write(fs, "/keys/a.pem", DkimKeys.toPem(a.getPrivate()));
		Dkim dkim = new Dkim();
		assertThrows(IOException.class, () -> dkim.addSigners("a.test:s1:/keys/a.pem,b.test:s2:/keys/missing.pem", null, fs));
		assertTrue(dkim.getSigners().isEmpty(), "nothing is used until every key is read");
	}

	@Test
	public void theLocalDiskStillWorksWithoutAFactory(@TempDir Path dir) throws Exception {
		KeyPair kp = DkimKeys.generate("rsa");
		Path pem = dir.resolve("local.pem");
		Files.write(pem, DkimKeys.toPem(kp.getPrivate()).getBytes(StandardCharsets.US_ASCII));
		List<DkimSigner> signers = Dkim.parseSigners("local.test:s1:" + pem, null);
		assertEquals(1, signers.size());
		assertEquals("local.test", signers.get(0).getDomain());
	}

	@Test
	public void theKeyOfADifferentFileSourceIsNotFoundOnTheLocalDisk(@TempDir Path dir) throws Exception {
		FileSourceFactory fs = memory();
		write(fs, "/keys/only-in-memory.pem", DkimKeys.toPem(DkimKeys.generate("rsa").getPrivate()));
		assertThrows(IOException.class, () -> Dkim.parseSigners("a.test:s1:/keys/only-in-memory.pem", null));
	}

	@Test
	public void thePublicSuffixListIsReadFromAnyFileSource() throws Exception {
		FileSourceFactory fs = memory();
		FileSource f = write(fs, "/lists/psl.dat", "// test list\ntest\nco.test\n");
		PublicSuffixList list = PublicSuffixList.load(f);
		assertEquals("co.test", list.publicSuffix("shop.example.co.test"));
		assertEquals("test", list.publicSuffix("example.test"));
	}

	@Test
	public void theServerReadsItsAliasesAndKeysFromTheStoresFileSystem() throws Exception {
		KeyPair kp = DkimKeys.generate("rsa");
		FileSourceFactory fs = memory();
		write(fs, "/etc/aliases.txt", "sales: tony, team@b.test\n");
		write(fs, "/keys/a.pem", DkimKeys.toPem(kp.getPrivate()));
		FileSource root = fs.createFileSource("/store");
		root.mkdirs();
		MailStoreSetup.setUp(root, "mx.a.test", "a.test", "aliases", "/etc/aliases.txt", "dkim.keys", "a.test:s1:/keys/a.pem");

		SmtpServer s = new SmtpServer(0, SmtpServer.SMTP_NAME, false);
		try {
			s.setMaildropRoot(root);
			s.setHostname("mx.a.test");
			s.startAndWait(10000);
			List<String> sales = s.getDeliveryConfig().getAliases().get("sales");
			assertEquals(List.of("tony", "team@b.test"), sales, "the aliases file on the store's file system");
			DkimSigner signer = s.getDeliveryConfig().dkimSignerFor("a.test");
			assertEquals("s1", signer.getSelector(), "the key file on the store's file system");

			// reading the settings again (an admin saving a change) finds the key there too, not on the local disk
			String used = s.getQueue().reload();
			assertNotNull(used);
			assertEquals("s1", s.getDeliveryConfig().dkimSignerFor("a.test").getSelector(), "after a reload");
		} finally {
			s.stop();
		}
	}
}
