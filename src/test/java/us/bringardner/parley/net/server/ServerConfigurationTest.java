package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Servers made from their own configuration: two servers of one launcher (one JVM) read the same
 * name from their own files and get different values; the system properties aren't touched; the
 * JVM's -D and the command line still win; a restart reads the files again.
 */
public class ServerConfigurationTest {

	/** What each configured server was made with, by id */
	static final Map<String, Properties> made = new ConcurrentHashMap<>();

	public abstract static class Configured implements ServerProvider {
		@Override
		public String description() {
			return "Configured " + id();
		}

		@Override
		public List<String> sharedSettingsFiles() {
			return Collections.singletonList("parley-cfgfamily.properties");
		}

		@Override
		public boolean usesConfiguration() {
			return true;
		}

		@Override
		public boolean enabled(Properties configuration) {
			return !"0".equals(configuration.getProperty("parley.cfg.port"));
		}

		@Override
		public ServerMain.Service create(ServerContext context, Properties configuration) {
			made.put(id(), configuration);
			return new ServerLauncherTest.FakeService(configuration.getProperty("parley.cfg.root"), null);
		}
	}

	public static class CfgA extends Configured {
		@Override
		public String id() {
			return "cfga";
		}
	}

	public static class CfgB extends Configured {
		@Override
		public String id() {
			return "cfgb";
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
		made.clear();
	}

	private void write(String name, String text) throws IOException {
		Files.write(new File(dir, name).toPath(), text.getBytes(StandardCharsets.UTF_8));
	}

	private void launcher(String... args) throws Exception {
		launcher = ServerMain.launcher("CfgProcess", args, dir, "cfga", "cfgb");
		launcher.init();
	}

	@Test
	public void oneNameTwoValues() throws Exception {
		write("parley-cfgfamily.properties", "parley.cfg.root=/family\nparley.cfg.shared=yes\n");
		write("parley-cfga.properties", "parley.cfg.root=/a\n");
		write("parley-cfgb.properties", "parley.cfg.root=/b\n");
		launcher();
		launcher.startAll();
		assertEquals("/a", made.get("cfga").getProperty("parley.cfg.root"));
		assertEquals("/b", made.get("cfgb").getProperty("parley.cfg.root"));
		assertEquals("yes", made.get("cfga").getProperty("parley.cfg.shared"));
		assertEquals("yes", made.get("cfgb").getProperty("parley.cfg.shared"));
		assertNull(System.getProperty("parley.cfg.root"), "the system properties aren't set");
		assertNull(System.getProperty("parley.cfg.shared"));
	}

	@Test
	public void aServerDoesntSeeAnotherServersFile() throws Exception {
		write("parley-cfga.properties", "parley.cfg.onlyA=1\n");
		launcher();
		launcher.startAll();
		assertEquals("1", made.get("cfga").getProperty("parley.cfg.onlyA"));
		assertNull(made.get("cfgb").getProperty("parley.cfg.onlyA"));
	}

	@Test
	public void commandLineWinsForEveryServer() throws Exception {
		write("parley-cfga.properties", "parley.cfg.root=/a\n");
		launcher("-Dparley.cfg.root=/cmd");
		launcher.startAll();
		assertEquals("/cmd", made.get("cfga").getProperty("parley.cfg.root"));
		assertEquals("/cmd", made.get("cfgb").getProperty("parley.cfg.root"));
	}

	@Test
	public void eachServerIsTurnedOffByItsOwnSettings() throws Exception {
		write("parley-cfgb.properties", "parley.cfg.port=0\n");
		launcher();
		launcher.startAll();
		assertEquals(ServerLauncher.State.RUNNING, launcher.getState("cfga"));
		assertEquals(ServerLauncher.State.OFF, launcher.getState("cfgb"));
	}

	@Test
	public void restartReadsTheFilesAgain() throws Exception {
		write("parley-cfga.properties", "parley.cfg.root=/one\n");
		launcher();
		launcher.startAll();
		write("parley-cfga.properties", "parley.cfg.root=/two\n");
		launcher.restart("cfga");
		assertEquals("/two", made.get("cfga").getProperty("parley.cfg.root"));
		assertEquals("/two", launcher.getConfiguration("cfga").getProperty("parley.cfg.root"));
		assertTrue(Arrays.asList(launcher.getSettingsFiles()).contains(new File(dir, "parley-cfgb.properties").getAbsolutePath()));
	}
}
