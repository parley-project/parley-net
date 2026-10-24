package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ServerLauncher: providers found at run time, settings files in order (the family's, then the
 * server's), start, stop and restart (with JMX too), a server stopping by itself, the shared context.
 */
public class ServerLauncherTest {

	/** A server that keeps the setting it was made with; it "listens" until stopped. */
	public static class FakeService implements ServerMain.Service {
		final String value;
		final CountDownLatch stopped = new CountDownLatch(1);
		final Object shared;

		FakeService(String value, Object shared) {
			this.value = value;
			this.shared = shared;
		}

		@Override
		public String name() {
			return "Fake";
		}

		@Override
		public void startAndWait(long timeoutMillis) throws IOException {
			if ("fail".equals(value)) {
				throw new IOException("can't listen");
			}
			if ("die".equals(value)) {
				Thread t = new Thread(() -> {
					try {
						Thread.sleep(300);
					} catch (InterruptedException e) {
						// stop now
					}
					stopped.countDown();
				});
				t.setDaemon(true);
				t.start();
			}
		}

		@Override
		public int port() {
			return 4242;
		}

		@Override
		public void stop(long timeoutMillis) {
			stopped.countDown();
		}

		@Override
		public void awaitStop() throws InterruptedException {
			stopped.await();
		}

		@Override
		public int connections() {
			return 3;
		}
	}

	static final AtomicReference<FakeService> last = new AtomicReference<>();

	public static class FakeProvider implements ServerProvider {
		@Override
		public String id() {
			return "fake";
		}

		@Override
		public String description() {
			return "Fake server";
		}

		@Override
		public List<String> sharedSettingsFiles() {
			return Collections.singletonList("parley-family.properties");
		}

		@Override
		public ServerMain.Service create(ServerContext context) throws Exception {
			Object shared = context.shared("fake.shared", Object.class, Object::new);
			FakeService s = new FakeService(System.getProperty("parley.fake.value"), shared);
			last.set(s);
			return s;
		}
	}

	@TempDir
	File dir;

	ServerLauncher launcher;

	@AfterEach
	public void close() {
		if (launcher != null) {
			launcher.close();
		}
		System.clearProperty("parley.fake.value");
		System.clearProperty("parley.fake.family");
	}

	private void write(String name, String text) throws IOException {
		Files.write(new File(dir, name).toPath(), text.getBytes(StandardCharsets.UTF_8));
	}

	private ServerLauncher launcher(String... args) throws Exception {
		launcher = ServerMain.launcher("FakeProcess", args, dir, "fake");
		launcher.init();
		return launcher;
	}

	@Test
	public void unknownServer() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> new ServerLauncher("x", new LaunchSettings(new java.util.Properties()), Arrays.asList("nope"), dir, new ServerContext()));
		assertTrue(e.getMessage().contains("nope") && e.getMessage().contains("fake"), e.getMessage());
	}

	@Test
	public void noServersListed() {
		IOException e = assertThrows(IOException.class, () -> ServerMain.launcher("x", new String[0], dir));
		assertTrue(e.getMessage().contains("parley.servers"), e.getMessage());
	}

	@Test
	public void serversFromLauncherFile() throws Exception {
		write(ServerMain.LAUNCHER_FILE, "parley.servers=fake\n");
		launcher = ServerMain.launcher("x", new String[0], dir);
		assertEquals(Arrays.asList("fake"), Arrays.asList(launcher.getServers()));
	}

	@Test
	public void settingsInOrder() throws Exception {
		write("parley-family.properties", "parley.fake.value=family\nparley.fake.family=yes\n");
		write("parley-fake.properties", "parley.fake.value=own\n");
		launcher();
		launcher.startAll();
		assertEquals("own", last.get().value);
		assertEquals("yes", System.getProperty("parley.fake.family"));
		assertEquals(2, launcher.getSettingsFiles().length);
	}

	@Test
	public void commandLineWins() throws Exception {
		write("parley-fake.properties", "parley.fake.value=own\n");
		launcher("-Dparley.fake.value=cmd");
		launcher.startAll();
		assertEquals("cmd", last.get().value);
	}

	@Test
	public void startStopRestartWithJmx() throws Exception {
		write("parley-fake.properties", "parley.fake.value=one\n");
		launcher();
		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		ObjectName server = new ObjectName("us.bringardner.parley:type=Server,name=fake");
		ObjectName proc = new ObjectName("us.bringardner.parley:type=Launcher,name=FakeProcess");
		assertTrue(mbs.isRegistered(server));
		assertTrue(mbs.isRegistered(proc));
		assertEquals("STOPPED", mbs.getAttribute(server, "State"));

		mbs.invoke(server, "start", null, null);
		assertEquals("RUNNING", mbs.getAttribute(server, "State"));
		assertEquals(4242, mbs.getAttribute(server, "Port"));
		assertEquals(3, mbs.getAttribute(server, "Connections"));
		FakeService first = last.get();

		write("parley-fake.properties", "parley.fake.value=two\n");
		mbs.invoke(server, "restart", null, null);
		FakeService second = last.get();
		assertEquals("two", second.value);
		assertEquals(0, first.stopped.getCount());
		assertSame(first.shared, second.shared, "the shared object lives as long as the launcher");

		mbs.invoke(server, "stop", null, null);
		assertEquals("STOPPED", mbs.getAttribute(server, "State"));
		assertNull(mbs.getAttribute(server, "Error"));

		String[] servers = (String[]) mbs.getAttribute(proc, "Servers");
		assertEquals(Arrays.asList("fake"), Arrays.asList(servers));
		launcher.close();
		launcher = null;
		assertTrue(!mbs.isRegistered(server));
	}

	@Test
	public void stopsByItself() throws Exception {
		launcher();
		CountDownLatch failed = new CountDownLatch(1);
		launcher.setOnFailure(id -> failed.countDown());
		launcher.startAll();
		last.get().stopped.countDown(); // not asked to stop
		assertTrue(failed.await(5, TimeUnit.SECONDS));
		assertEquals(ServerLauncher.State.FAILED, launcher.getState("fake"));
		assertNotNull(launcher.getServer("fake").getError());
		assertTrue(!launcher.isAnyRunning());
	}

	@Test
	public void startFails() throws Exception {
		launcher("-Dparley.fake.value=fail");
		IOException e = assertThrows(IOException.class, () -> launcher.startAll());
		assertTrue(e.getMessage().contains("can't listen"), e.getMessage());
		assertEquals(ServerLauncher.State.FAILED, launcher.getState("fake"));
	}

	@Test
	public void secondLauncherGetsInstanceName() throws Exception {
		launcher();
		ServerLauncher other = ServerMain.launcher("FakeProcess", new String[0], dir, "fake");
		try {
			other.init();
			assertTrue(ManagementFactory.getPlatformMBeanServer()
					.isRegistered(new ObjectName("us.bringardner.parley:type=Server,name=fake,instance=2")));
		} finally {
			other.close();
		}
	}

	// ------------------------------------------------------------------ as a process (ServerMain.main)

	private Process process(String... args) throws Exception {
		List<String> cmd = new java.util.ArrayList<>(Arrays.asList(new File(System.getProperty("java.home"), "bin/java").getPath(),
				"-cp", System.getProperty("java.class.path"), ServerMain.class.getName()));
		cmd.addAll(Arrays.asList(args));
		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
		pb.environment().put("PARLEY_CONF", new File(dir, "parley.properties").getPath());
		return pb.start();
	}

	private static String read(Process p) throws IOException {
		return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
	}

	@Test
	public void processRunsUntilStopped() throws Exception {
		org.junit.jupiter.api.Assumptions.assumeTrue(File.separatorChar == '/', "SIGTERM: not on Windows");
		write(ServerMain.LAUNCHER_FILE, "parley.servers=fake\n");
		Process p = process();
		try {
			java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
			StringBuilder out = new StringBuilder();
			String line;
			boolean started = false;
			while (!started && (line = r.readLine()) != null) {
				out.append(line).append('\n');
				started = line.equals("Fake server (fake) started on port 4242");
			}
			assertTrue(started, out.toString());
			Thread.sleep(500);
			assertTrue(p.isAlive(), "the process lives while the server runs");
			p.destroy(); // SIGTERM
			assertTrue(p.waitFor(20, TimeUnit.SECONDS), "SIGTERM stops the server and the process");
		} finally {
			p.destroyForcibly();
		}
	}

	@Test
	public void processExitsWithOneWhenTheServerStopsByItself() throws Exception {
		Process p = process("-Dparley.servers=fake", "-Dparley.fake.value=die");
		try {
			assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
			assertEquals(1, p.exitValue(), "a failure, for the service manager");
		} finally {
			p.destroyForcibly();
		}
	}

	@Test
	public void processExitsWithOneForAnUnknownServer() throws Exception {
		Process p = process("parley.servers", "fake,nope");
		try {
			assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
			assertEquals(1, p.exitValue());
			String out = read(p);
			assertTrue(out.contains("Unknown server [nope]") && out.contains("known: [fake"), out);
		} finally {
			p.destroyForcibly();
		}
	}
}
