package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.net.TestFiles;

/** A user file is read again when it changes, so users can change while a server runs. */
public class FileUserRegistryReloadTest {

	@TempDir
	Path tempDir;

	private FileSource dir;

	@BeforeEach
	public void dir() throws Exception {
		dir = TestFiles.local(tempDir);
	}

	@AfterEach
	public void clear() {
		System.clearProperty("reloadTest." + FileUserRegistry.PROP_FILE_NAME);
		System.clearProperty(FileUserRegistry.PROP_RELOAD_INTERVAL);
	}

	private static void write(FileSource f, String text, long modified) throws Exception {
		TestFiles.write(f, text);
		f.setLastModified(modified);
	}

	@Test
	public void changesAreReadAgain() throws Exception {
		FileSource f = dir.getChild("users.txt");
		long t = System.currentTimeMillis() - 60000;
		write(f, "tony , secret , READ\n", t);
		System.setProperty("reloadTest." + FileUserRegistry.PROP_FILE_NAME, f.getPath());
		try (FileUserRegistry registry = new FileUserRegistry()) {
			registry.initialize("reloadTest");
			assertNotNull(registry.findPrincipal("tony"));
			assertNull(registry.findPrincipal("jose"));

			write(f, "tony , secret , READ\njose , other , READ|WRITE\n", t + 2000);
			assertTrue(registry.reloadNow());
			assertNotNull(registry.findPrincipal("jose"));
			assertEquals(AuthenticationResult.Status.AUTHENTICATED, registry.authenticate(
					new PasswordCredential("jose", "other".toCharArray(), Requester.withoutAddress("test"))).getStatus());
			assertFalse(registry.reloadNow(), "unchanged");

			// checked by the lookups themselves, at most every reloadInterval
			System.setProperty(FileUserRegistry.PROP_RELOAD_INTERVAL, "0");
			write(f, "jose , other , READ\n", t + 4000);
			assertNotNull(registry.findPrincipal("tony"), "0: never checked");
			assertTrue(registry.reloadNow());
			assertNull(registry.findPrincipal("tony"), "removed");
			assertEquals("jose", registry.findPrincipal("jose").getName());
		}
	}

	@Test
	public void anUnreadableFileKeepsTheUsers() throws Exception {
		FileSource f = dir.getChild("users.txt");
		long t = System.currentTimeMillis() - 60000;
		write(f, "tony , secret , READ\n", t);
		System.setProperty("reloadTest." + FileUserRegistry.PROP_FILE_NAME, f.getPath());
		FileUserRegistry registry = new FileUserRegistry();
		registry.initialize("reloadTest");
		assertTrue(f.delete());
		assertFalse(registry.reloadNow());
		assertNotNull(registry.findPrincipal("tony"), "the users read before stay");
		registry.close();
	}
}
