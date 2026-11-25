package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.net.TestFiles;
import us.bringardner.parley.net.nio.NioServer;

/**
 * ServerMain: the settings (the file, the command line winning), and a process run by
 * {@link ServerMain#run} ({@link #main(String[])}): it stays up, stops on SIGTERM, and exits with 1
 * when a server can't start. Its two servers are a Server and a NioServer, both an {@link IBaseServer}.
 */
public class ServerMainTest {

	@TempDir
	Path tempDir;

	private FileSource dir;

	@BeforeEach
	public void dir() throws Exception {
		dir = TestFiles.local(tempDir);
	}

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

	private FileSource file(String name, String... lines) throws Exception {
		return file(dir, name, lines);
	}

	private static FileSource file(FileSource in, String name, String... lines) throws Exception {
		return TestFiles.write(in.getChild(name), String.join("\n", lines) + "\n");
	}

	@Test
	public void theCommandLineIsAppliedAsSystemProperties() throws Exception {
		used("test.sm.port", "test.sm.other");
		System.setProperty("test.sm.port", "7"); // as java -Dtest.sm.port=7 would
		ServerMain.configure("Test", new String[] {"-Dtest.sm.port=2", "test.sm.other", "x"});
		assertEquals("2", System.getProperty("test.sm.port"), "the command line wins over the JVM's -D");
		assertEquals("x", System.getProperty("test.sm.other"), "name value");
	}

	@Test
	public void secretsAreNotPrinted() {
		assertEquals("********", ServerMain.printable("parley.mail.smtp.relayPassword", "pw"));
		assertEquals("********", ServerMain.printable("parley.mail.imap.keyStorePassword", "pw"));
		assertEquals("********", ServerMain.printable("x.clientSecret", "pw"));
		assertEquals("2525", ServerMain.printable("parley.mail.smtp.port", "2525"));
	}

	// ------------------------------------------------------------------ the process

	/** A server that accepts connections (and does nothing with them) */
	private static Server server(int port, String name) {
		Server s = new Server(port, name) {
			@Override
			protected String getSettingsFileName() {
				return "parley-test.properties";
			}

			@Override
			protected String getSettingsFileProperty() {
				return "test.sm.configFile";
			}
		};
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
			public AuthorizationResult checkPermission(ParleyPermission needed, ProtectedResource resource) {
				return AuthorizationResult.allowed("everyone");
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
		NioServer s = new NioServer(port, name) {
			@Override
			protected String getSettingsFileName() {
				return "parley-test.properties";
			}

			@Override
			protected String getSettingsFileProperty() {
				return "test.sm.configFile";
			}
		};
		s.setHandlerFactory(() -> (connection, frame) -> { });
		return s;
	}

	/**
	 * Two servers, on the ports test.sm.port1 and test.sm.port2: a thread-per-connection Server and
	 * a NioServer, both run through {@link ServerMain#service(IBaseServer, String)}
	 */
	public static void main(String[] args) throws Exception {
		ServerMain.run("TestServer", args, () -> {
			Server one = server(0, "one");
			NioServer two = nioServer(0, "two");
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
		List<String> cmd = new ArrayList<String>(Arrays.asList(FileSource.of(System.getProperty("java.home"), "bin").getChild("java").getPath(),
				"-cp", System.getProperty("java.class.path"), ServerMainTest.class.getName()));
		cmd.addAll(Arrays.asList(args));
		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
		pb.environment().put("PARLEY_CONF", dir.getChild("parley.properties").getPath());
		return pb.start();
	}

	@Test
	public void runsUntilStopped() throws Exception {
		assumeTrue(!FileSourceFactory.isWindows(), "SIGTERM: not on Windows");
		// (the settings file in CONF, read without being named)
		int twoPort;
		try (ServerSocket free = new ServerSocket(0)) {
			twoPort = free.getLocalPort();
		}
		file("parley-test.properties", "one.port=0", "two.port="+twoPort);
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
			assertTrue(out.toString().contains("TestServer two started on port "+twoPort), "its file was read: "+out);
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
			Process p = process("-Dtwo.port="+taken.getLocalPort());
			try {
				assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
				assertEquals(1, p.exitValue());
			} finally {
				p.destroyForcibly();
			}
		}
	}
}
