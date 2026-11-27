package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.logging.testing.ErrorsExpected;
import us.bringardner.parley.core.BaseObject;

/**
 * A server finds and reads its own settings file when it starts, through BaseObject (the include
 * resolvers), and refuses to start, saying everything that is wrong, when it can't.
 */
public class ServerSettingsAtStartTest {

	private static final String CONFIG = "test.sas.configFile";

	@TempDir
	Path tempDir;

	@AfterEach
	public void clear() {
		BaseObject.clearSettings();
		System.clearProperty(CONFIG);
		System.clearProperty("sas.port");
	}

	/** a server whose settings folder is the temp folder, with a shared file parley-test-shared.properties and default file parley-test.properties */
	private Server folderServer() {
		Server s = new Server(0, "sas") {
			@Override
			protected String getSettingsFolder() {
				return tempDir.toString();
			}

			@Override
			protected String getSharedSettingsFileName() {
				return "parley-test-shared.properties";
			}

			@Override
			protected String getSettingsFileName() {
				return "parley-test.properties";
			}
		};
		s.setConnectionFactory(socket -> new us.bringardner.parley.net.Connection(socket, true) {
			@Override
			public javax.net.ssl.SSLContext getSSLContext(String sslOrTls) {
				return null;
			}
		});
		s.setProcessorFactory(() -> null);
		return s;
	}

	@Test
	public void theServersOwnFileWinsOverTheSharedOne() throws Exception {
		int port = free();
		file("parley-test-shared.properties", "sas.greeting=shared", "sas.other=shared", "sas.port=" + free());
		file("parley-test.properties", "sas.greeting=own", "sas.port=" + port);
		Server s = folderServer();
		try {
			s.startAndWait(10000);
			assertEquals("own", s.getProperty("sas.greeting"));
			assertEquals("shared", s.getProperty("sas.other"));
			assertEquals(port, s.getLocalPort());
		} finally {
			s.stop(5000, false);
		}
	}

	@Test
	public void onlyTheSharedFileIsFine() throws Exception {
		file("parley-test-shared.properties", "sas.other=shared");
		Server s = folderServer();
		try {
			s.startAndWait(10000);
			assertEquals("shared", s.getProperty("sas.other"));
		} finally {
			s.stop(5000, false);
		}
	}

	/** a server on the default port 0 (any free port) whose settings file is named by test.sas.configFile */
	private static Server server(List<String> checked) {
		Server s = new Server(0, "sas") {
			@Override
			protected String getSettingsFileProperty() {
				return CONFIG;
			}

			@Override
			protected void checkSettings(List<String> problems) {
				super.checkSettings(problems);
				if (checked != null) {
					problems.addAll(checked);
				}
			}
		};
		s.setConnectionFactory(socket -> new us.bringardner.parley.net.Connection(socket, true) {
			@Override
			public javax.net.ssl.SSLContext getSSLContext(String sslOrTls) {
				return null;
			}
		});
		s.setProcessorFactory(() -> null);
		return s;
	}

	private Path file(String name, String... lines) throws IOException {
		Path ret = tempDir.resolve(name);
		Files.write(ret, (String.join("\n", lines) + "\n").getBytes(StandardCharsets.UTF_8));
		return ret;
	}

	private static int free() throws IOException {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}

	@Test
	public void theFilesPortReplacesTheConstructorsDefault() throws Exception {
		int port = free();
		System.setProperty(CONFIG, file("a.properties", "sas.port=" + port).toString());
		Server s = server(null);
		assertEquals(0, s.getPort(), "before start the file isn't read");
		try {
			s.startAndWait(10000);
			assertEquals(port, s.getPort());
			assertEquals(port, s.getLocalPort());
		} finally {
			s.stop(5000, false);
		}
	}

	@Test
	public void aSystemPropertyWinsOverTheFile() throws Exception {
		int fromFile = free();
		int fromD = free();
		System.setProperty(CONFIG, file("a.properties", "sas.port=" + fromFile).toString());
		System.setProperty("sas.port", "" + fromD);
		Server s = server(null);
		try {
			s.startAndWait(10000);
			assertEquals(fromD, s.getLocalPort());
		} finally {
			s.stop(5000, false);
		}
	}

	@ErrorsExpected
	@Test
	public void aFileThatIsNamedHasToBeThere() throws Exception {
		System.setProperty(CONFIG, tempDir.resolve("missing.properties").toString());
		Server s = server(null);
		IOException e = assertThrows(IOException.class, () -> s.startAndWait(2000));
		assertTrue(e.getMessage().contains("missing.properties"), e.getMessage());
		assertTrue(e.getMessage().contains("isn't there"), e.getMessage());
	}

	@Test
	public void noFileIsFine() throws Exception {
		Server s = server(null);
		try {
			s.startAndWait(10000);
			assertTrue(s.getLocalPort() > 0);
		} finally {
			s.stop(5000, false);
		}
	}

	@Test
	public void theFileMayIncludeAnother() throws Exception {
		int port = free();
		file("base.properties", "sas.port=" + port);
		System.setProperty(CONFIG, file("a.properties", "parley.include=base.properties").toString());
		Server s = server(null);
		try {
			s.startAndWait(10000);
			assertEquals(port, s.getLocalPort());
		} finally {
			s.stop(5000, false);
		}
	}

	@Test
	public void theFileIsUtf8() throws Exception {
		System.setProperty(CONFIG, file("a.properties", "sas.greeting=Grüße — café").toString());
		Server s = server(null);
		try {
			s.startAndWait(10000);
			assertEquals("Grüße — café", s.getProperty("sas.greeting"));
		} finally {
			s.stop(5000, false);
		}
	}

	@ErrorsExpected
	@Test
	public void everyProblemIsReportedAndTheServerDoesNotStart() throws Exception {
		System.setProperty(CONFIG, file("a.properties", "sas.port=70000").toString());
		Server s = server(List.of("sas.root isn't set: it names the folder to serve"));
		PrintStream before = System.err;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		System.setErr(new PrintStream(out, true, "UTF-8"));
		IOException e;
		try {
			e = assertThrows(IOException.class, () -> s.startAndWait(2000));
		} finally {
			System.setErr(before);
		}
		String err = out.toString("UTF-8");
		for (String text : new String[] { e.getMessage(), err }) {
			assertTrue(text.contains("2 problems"), text);
			assertTrue(text.contains("1) sas.port is 70000"), text);
			assertTrue(text.contains("2) sas.root isn't set"), text);
		}
		assertNull(s.getStartupError() == null ? null : null);
		assertNotNull(s.getStartupError());
		assertTrue(!s.isRunning());
	}

	@Test
	public void aNameNothingReadsInTheFileIsWarnedAbout() throws Exception {
		Path f = file("a.properties", "parley.fake.vlaue=x");
		System.setProperty(CONFIG, f.toString());
		Server s = server(null);
		PrintStream before = System.err;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		System.setErr(new PrintStream(out, true, "UTF-8"));
		try {
			s.startAndWait(10000);
		} finally {
			System.setErr(before);
			s.stop(5000, false);
		}
		String err = out.toString("UTF-8");
		assertTrue(err.contains("warning: parley.fake.vlaue (" + f + ") is not a setting"), err);
	}

	@Test
	public void theWarningNamesTheIncludedFileThatHasTheName() throws Exception {
		Path base = file("base.properties", "parley.fake.vlaue=x");
		System.setProperty(CONFIG, file("a.properties", "parley.include=base.properties").toString());
		Server s = server(null);
		PrintStream before = System.err;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		System.setErr(new PrintStream(out, true, "UTF-8"));
		try {
			s.startAndWait(10000);
		} finally {
			System.setErr(before);
			s.stop(5000, false);
		}
		String err = out.toString("UTF-8");
		assertTrue(err.contains("parley.fake.vlaue (" + base + ") is not a setting"), err);
	}
}
