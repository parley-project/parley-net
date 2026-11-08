package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.net.TestFiles;
import us.bringardner.parley.net.nio.NioServer;

/**
 * To-Do 2.16: the lists of known settings, the start-up warning for a setting nothing reads, and
 * that the lists of parley-core, parley-files and parley-net have every name their code reads.
 */
public class KnownSettingsTest {

	@TempDir
	Path tempDir;

	@Test
	public void namesAndPatterns() {
		KnownSettings k = KnownSettings.of(
				"# a comment",
				"parley.mail.root   # after a name too",
				"parley.mail.{pop3,pop3s}.requireTls",
				"parley.*.plugins.path",
				"parley.core.log.level.**");
		assertTrue(k.isKnown("parley.mail.root"));
		assertFalse(k.isKnown("parley.mail.rot"));
		assertFalse(k.isKnown("parley.mail.root.x"), "a whole name, not its start");
		assertTrue(k.isKnown("parley.mail.pop3.requireTls"));
		assertTrue(k.isKnown("parley.mail.pop3s.requireTls"));
		assertFalse(k.isKnown("parley.mail.imap.requireTls"));
		assertTrue(k.isKnown("parley.fsh.plugins.path"));
		assertFalse(k.isKnown("parley.a.b.plugins.path"), "* is one segment");
		assertTrue(k.isKnown("parley.core.log.level.us.bringardner.parley.mail"));
		assertFalse(k.isKnown("parley.core.log.level"), "** is one segment or more");
	}

	@Test
	public void namesUnderEveryServersPrefix() {
		KnownSettings k = KnownSettings.of("<server>.port", "prefix parley.mail.pop3", "prefix parley.ftp");
		assertTrue(k.isKnown("parley.mail.pop3.port"));
		assertTrue(k.isKnown("parley.ftp.port"));
		assertFalse(k.isKnown("parley.mail.imap.port"), "no list has that prefix");
		k.addPrefix("parley.mail.imap");
		assertTrue(k.isKnown("parley.mail.imap.port"));
		assertEquals(List.of("parley.mail.pop3", "parley.ftp", "parley.mail.imap"), k.prefixes());
	}

	@Test
	public void badLinesAreRefused() {
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("parley.a parley.b"));
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("parley..b"));
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("parley.**.b"));
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("parley.a$b"));
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("renamed JPop3.port"));
		assertThrows(IllegalArgumentException.class, () -> KnownSettings.of("prefix mail.pop3"));
	}

	@Test
	public void warningsForWhatNothingReads() {
		KnownSettings k = KnownSettings.of("parley.mail.root", "<server>.port", "prefix parley.mail.pop3",
				"renamed JPop3.root parley.mail.root", "renamed parley.mail.sharedStore parley.mail.store.sharing");
		Map<String, List<String>> set = new LinkedHashMap<>();
		set.put("/etc/parley/parley-mail.properties", List.of("parley.mail.root", "parley.mail.pop3.port",
				"parley.mail.pop3.prot", "JPop3.root", "JSmtp.port", "Pop3Server.port", "parley.mail.sharedStore"));
		set.put("a -D setting", List.of("java.version", "user.home", "javax.net.ssl.trustStore", "parley.mail.root",
				"us.bringardner.parley.core.util.SocketClient.connectTimeout", "port"));
		List<String> w = k.check(set);
		assertEquals(5, w.size(), w.toString());
		assertTrue(w.contains("JPop3.root (/etc/parley/parley-mail.properties) is no longer read: since 2.0.0 it is parley.mail.root"), w.toString());
		assertTrue(w.contains("JSmtp.port (/etc/parley/parley-mail.properties) looks like a 1.x setting, which 2.0.0 no longer reads: see the module's CHANGELOG for its new name"), w.toString());
		assertTrue(w.contains("Pop3Server.port (/etc/parley/parley-mail.properties) looks like a 1.x setting, which 2.0.0 no longer reads: see the module's CHANGELOG for its new name"), w.toString());
		assertTrue(w.contains("parley.mail.pop3.prot (/etc/parley/parley-mail.properties) is not a setting any Parley module here reads: check the spelling"), w.toString());
		assertTrue(w.contains("parley.mail.sharedStore (/etc/parley/parley-mail.properties) is no longer read: since 2.0.0 it is parley.mail.store.sharing"), w.toString());
	}

	@Test
	public void theListsOnTheClassPathAreRead() throws IOException {
		KnownSettings k = KnownSettings.load();
		assertTrue(k.isKnown("parley.core.forceTlsVersion"), "parley-core's");
		assertTrue(k.isKnown("parley.files.lockDirectory"), "parley-files'");
		assertTrue(k.isKnown("parley.net.acl.hashWait"), "parley-net's");
		assertTrue(k.isKnown("parley.fake.port"), "a framework name under a test server's prefix");
		assertFalse(k.isKnown("parley.fake.prot"));
	}

	/** Every parley.* name core, files and net spell out in their code is in their lists */
	@Test
	public void coreFilesAndNetListEveryNameTheirCodeHas() throws IOException {
		KnownSettings k = KnownSettings.load();
		for (Class<?> c : new Class<?>[] { BaseObject.class, FileSourceFactory.class, ServerMain.class }) {
			List<String> found = KnownSettings.settingConstants(c);
			assertFalse(found.isEmpty(), c.getName());
			assertEquals(List.of(), k.undeclared(found), "not in the list of " + c.getName() + "'s module");
		}
	}

	/** Every name a running server reads under its prefix is in the lists */
	@Test
	public void theFrameworksServerSettingsAreListed() throws Exception {
		KnownSettings k = KnownSettings.load().addPrefix("parley.example");
		KnownSettings.RecordingProperties nio = new KnownSettings.RecordingProperties();
		NioServer n = new NioServer(0, "parley.example");
		n.setConfiguration(nio);
		n.setHandlerFactory(() -> (connection, frame) -> { });
		n.startAndWait(5000);
		try (Socket s = new Socket("localhost", n.getLocalPort())) {
			s.getOutputStream().write("x\n".getBytes(StandardCharsets.US_ASCII));
			Thread.sleep(200);
		} finally {
			n.stop(5000, false);
		}
		List<String> asked = new ArrayList<>(nio.asked());
		assertTrue(asked.contains("parley.example.maxConnections"), asked.toString());
		assertEquals(List.of(), k.undeclared(asked));
	}

	/** A server started on its own (its main, through ServerMain.configure) is checked too */
	@Test
	public void aServerOnItsOwnWarnsToo() throws Exception {
		FileSource dir = TestFiles.local(tempDir);
		FileSource own = TestFiles.write(dir.getChild("parley-fake.properties"),
				"parley.fake.port=1\nparley.fake.prot=2\n");
		try {
			String err = stderr(() -> ServerMain.configure("FakeServer", new String[] { "-Dparley.fake.vlaue=x" }, "parley.fake.configFile",
					"parley-fake.properties", dir));
			assertTrue(err.contains("FakeServer: warning: parley.fake.prot (" + own.getPath() + ") is not a setting"), err);
			assertTrue(err.contains("FakeServer: warning: parley.fake.vlaue (the command line) is not a setting"), err);
			assertFalse(err.contains("parley.fake.port "), err);
		} finally {
			for (String n : new String[] { "parley.fake.port", "parley.fake.prot", "parley.fake.vlaue", "parley.fake.configFile" }) {
				System.clearProperty(n);
			}
		}
	}

	private interface Action {
		void run() throws Exception;
	}

	private static String stderr(Action a) throws Exception {
		PrintStream before = System.err;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		System.setErr(new PrintStream(out, true, "UTF-8"));
		try {
			a.run();
		} finally {
			System.setErr(before);
		}
		return out.toString("UTF-8");
	}

	@Test
	public void settingNames() {
		assertTrue(KnownSettings.isSettingName("parley.servers"));
		assertTrue(KnownSettings.isSettingName("parley.mail.pop3.requireTls"));
		assertFalse(KnownSettings.isSettingName("parley"));
		assertFalse(KnownSettings.isSettingName("parley.mail.*"));
		assertFalse(KnownSettings.isSettingName("parley-mail.properties"));
		assertNull(KnownSettings.of("parley.a.b").renamedTo("parley.a.b"));
		assertTrue(KnownSettings.looksOld("JDns.properties.x"));
		assertFalse(KnownSettings.looksOld("java.version"));
		assertFalse(KnownSettings.looksOld("us.bringardner.parley.core.util.SocketClient.port"));
		Set<String> none = Set.of();
		assertEquals(List.of(), KnownSettings.of().check(Map.of("x", none)));
	}
}
