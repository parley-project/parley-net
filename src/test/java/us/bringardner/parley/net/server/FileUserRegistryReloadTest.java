package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.iam.Requester;

/** A user file is read again when it changes, so users can change while a server runs. */
public class FileUserRegistryReloadTest {

	@TempDir
	File dir;

	@AfterEach
	public void clear() {
		System.clearProperty("reloadTest." + FileUserRegistry.PROP_FILE_NAME);
		System.clearProperty(FileUserRegistry.PROP_RELOAD_INTERVAL);
	}

	private static void write(File f, String text, long modified) throws Exception {
		Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
		f.setLastModified(modified);
	}

	@Test
	public void changesAreReadAgain() throws Exception {
		File f = new File(dir, "users.txt");
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
		File f = new File(dir, "users.txt");
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
