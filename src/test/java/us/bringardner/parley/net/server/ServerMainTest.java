package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.nio.NioServer;

/**
 * ServerMain: the settings (the file, the command line winning), and a process run by
 * {@link ServerMain#run} ({@link #main(String[])}): it stays up, stops on SIGTERM, and exits with 1
 * when a server can't start. Its two servers are a Server and a NioServer, both an {@link IBaseServer}.
 */
public class ServerMainTest {

	@TempDir
	File dir;

	private final List<String> set = new ArrayList<String>();

	@AfterEach
	public void clear() {
		for (String p : set) {
			System.clearProperty(p);
		}
	}

	private void used(String... names) {
		set.addAll(Arrays.asList(names));
	}

	private File file(String name, String... lines) throws Exception {
		File f = new File(dir, name);
		Files.write(f.toPath(), Arrays.asList(lines));
		return f;
	}

	@Test
	public void theCommandLineWinsOverTheFile() throws Exception {
		used("test.sm.configFile", "test.sm.port", "test.sm.root", "test.sm.other");
		file("parley-test.properties", "test.sm.port=1", "test.sm.root=/from/file");
		ServerMain.configure("Test", new String[] {"-Dtest.sm.port=2", "test.sm.other", "x"}, "test.sm.configFile", "parley-test.properties", dir);
		assertEquals("2", System.getProperty("test.sm.port"), "the command line wins");
		assertEquals("/from/file", System.getProperty("test.sm.root"));
		assertEquals("x", System.getProperty("test.sm.other"), "name value");
		assertEquals(new File(dir, "parley-test.properties").getPath(), System.getProperty("test.sm.configFile"));
	}

	@Test
	public void theJvmsDashDWinsOverTheFile() throws Exception {
		used("test.sm.configFile", "test.sm.port", "test.sm.root");
		System.setProperty("test.sm.port", "7"); // as java -Dtest.sm.port=7 would
		file("parley-test.properties", "test.sm.port=1", "test.sm.root=/from/file");
		ServerMain.configure("Test", new String[0], "test.sm.configFile", "parley-test.properties", dir);
		assertEquals("7", System.getProperty("test.sm.port"), "the JVM's -D wins over the file");
		assertEquals("/from/file", System.getProperty("test.sm.root"));
		ServerMain.configure("Test", new String[] {"-Dtest.sm.port=8"}, "test.sm.configFile", "parley-test.properties", dir);
		assertEquals("8", System.getProperty("test.sm.port"), "the command line wins over both");
	}

	@Test
	public void theFileIsUtf8OrLatin1() throws Exception {
		File utf8 = new File(dir, "utf8.properties");
		Files.write(utf8.toPath(), "greeting=Gr\u00fc\u00dfe \u2014 caf\u00e9\n".getBytes(StandardCharsets.UTF_8));
		assertEquals("Gr\u00fc\u00dfe \u2014 caf\u00e9", ServerMain.load(utf8).getProperty("greeting"));
		File latin1 = new File(dir, "latin1.properties");
		Files.write(latin1.toPath(), "greeting=caf\u00e9\n".getBytes(StandardCharsets.ISO_8859_1));
		assertEquals("caf\u00e9", ServerMain.load(latin1).getProperty("greeting"), "not valid UTF-8: ISO-8859-1");
	}

	@Test
	public void secretsAreNotPrinted() {
		assertEquals("********", ServerMain.printable("parley.mail.smtp.relayPassword", "pw"));
		assertEquals("********", ServerMain.printable("parley.mail.imap.keyStorePassword", "pw"));
		assertEquals("********", ServerMain.printable("x.clientSecret", "pw"));
		assertEquals("2525", ServerMain.printable("parley.mail.smtp.port", "2525"));
	}

	@Test
	public void aNamedFileInsteadOfTheDefault() throws Exception {
		used("test.sm.configFile", "test.sm.port");
		file("parley-test.properties", "test.sm.port=1");
		File other = file("other.properties", "test.sm.port=3");
		ServerMain.configure("Test", new String[] {"-Dtest.sm.configFile="+other.getPath()}, "test.sm.configFile", "parley-test.properties", dir);
		assertEquals("3", System.getProperty("test.sm.port"));
	}

	@Test
	public void noFileNoDefault() throws Exception {
		used("test.sm.configFile", "test.sm.port");
		ServerMain.configure("Test", new String[0], "test.sm.configFile", "parley-test.properties", dir);
		assertNull(System.getProperty("test.sm.port"));
		assertNull(System.getProperty("test.sm.configFile"), "no default file: nothing named");
	}

	@Test
	public void aMissingNamedFileIsAnError() {
		used("test.sm.configFile");
		assertThrows(java.io.IOException.class, () -> ServerMain.configure("Test",
				new String[] {"-Dtest.sm.configFile="+new File(dir, "none").getPath()}, "test.sm.configFile", null, dir));
	}

	@Test
	public void confDir() {
		assertEquals(new File("/etc/parley").getAbsoluteFile(), ServerMain.confDir(Collections.emptyMap(), false));
		assertEquals(new File(dir, "x.properties").getAbsoluteFile().getParentFile(),
				ServerMain.confDir(Collections.singletonMap("PARLEY_CONF", new File(dir, "x.properties").getPath()), false));
	}

	// ------------------------------------------------------------------ the process

	/** A server that accepts connections (and does nothing with them) */
	private static Server server(int port, String name) {
		Server s = new Server(port, name);
		s.setConnectionFactory(socket -> new us.bringardner.parley.net.Connection(socket, true) {
			@Override
			public javax.net.ssl.SSLContext getSSLContext(String sslOrTls) {
				return null;
			}
		});
		s.setProcessorFactory(() -> new AbstractCommandProcessor() {
			private static final long serialVersionUID = 1L;

			@Override
			public String translateResponseCode(int code) {
				return ""+code;
			}

			@Override
			public boolean isAuthorized(IPermission action) {
				return true;
			}

			@Override
			public ICommandFactory getCommandFactory() {
				return context -> null;
			}
		});
		return s;
	}

	/** A non-blocking server that accepts connections (and does nothing with them) */
	private static NioServer nioServer(int port, String name) {
		NioServer s = new NioServer(port, name);
		s.setHandlerFactory(() -> (connection, frame) -> { });
		return s;
	}

	/**
	 * Two servers, on the ports test.sm.port1 and test.sm.port2: a thread-per-connection Server and
	 * a NioServer, both run through {@link ServerMain#service(IBaseServer, String)}
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.run("TestServer", args, "test.sm.configFile", "parley-test.properties", () -> {
			Server one = server(Integer.getInteger("test.sm.port1", 0), "one");
			NioServer two = nioServer(Integer.getInteger("test.sm.port2", 0), "two");
			if (Boolean.getBoolean("test.sm.stopByThemselves")) {
				// both stop a moment after starting, as a server that fails while running would
				Thread t = new Thread(() -> {
					try {
						while (!one.isRunning() || two.getLocalPort() <= 0) {
							Thread.sleep(50);
						}
						Thread.sleep(300);
						one.stop(5000, false);
						two.stop(5000, false);
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}, "stopper");
				t.setDaemon(true);
				t.start();
			}
			return Arrays.asList(ServerMain.service(one, "TestServer one"), ServerMain.service(two, "TestServer two"));
		});
	}

	private Process process(String... args) throws Exception {
		List<String> cmd = new ArrayList<String>(Arrays.asList(new File(System.getProperty("java.home"), "bin/java").getPath(),
				"-cp", System.getProperty("java.class.path"), ServerMainTest.class.getName()));
		cmd.addAll(Arrays.asList(args));
		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
		pb.environment().put("PARLEY_CONF", new File(dir, "parley.properties").getPath());
		return pb.start();
	}

	@Test
	public void runsUntilStopped() throws Exception {
		assumeTrue(File.separatorChar == '/', "SIGTERM: not on Windows");
		// (the settings file in CONF, read without being named)
		file("parley-test.properties", "test.sm.port1=0", "test.sm.port2=0");
		Process p = process();
		try {
			BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
			StringBuilder out = new StringBuilder();
			int started = 0;
			String line;
			while( started < 2 && (line = r.readLine()) != null ) {
				out.append(line).append('\n');
				if( line.matches("TestServer (one|two) started on port [1-9][0-9]*") ) {
					started++;
				}
			}
			assertEquals(2, started, out.toString());
			assertTrue(out.toString().contains("Loaded properties from"), out.toString());
			Thread.sleep(500);
			assertTrue(p.isAlive(), "the process lives while the servers run");
			p.destroy();	// SIGTERM
			assertTrue(p.waitFor(20, TimeUnit.SECONDS), "SIGTERM stops the servers and the process");
		} finally {
			p.destroyForcibly();
		}
	}

	@Test
	public void exitsWithOneWhenTheServersStopByThemselves() throws Exception {
		Process p = process("-Dtest.sm.stopByThemselves=true");
		try {
			assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
			assertEquals(1, p.exitValue(), "a failure, for the service manager");
		} finally {
			p.destroyForcibly();
		}
	}

	@Test
	public void exitsWithOneWhenAServerCannotStart() throws Exception {
		try (ServerSocket taken = new ServerSocket(0)) {
			Process p = process("-Dtest.sm.port2="+taken.getLocalPort());
			try {
				assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
				assertEquals(1, p.exitValue());
			} finally {
				p.destroyForcibly();
			}
		}
	}
}
