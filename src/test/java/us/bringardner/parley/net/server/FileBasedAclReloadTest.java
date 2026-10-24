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

/** A user file is read again when it changes, so users can change while a server runs. */
public class FileBasedAclReloadTest {

	@TempDir
	File dir;

	@AfterEach
	public void clear() {
		System.clearProperty("reloadTest." + FileBasedAcl.PROP_FILE_NAME);
		System.clearProperty(FileBasedAcl.PROP_RELOAD_SECONDS);
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
		System.setProperty("reloadTest." + FileBasedAcl.PROP_FILE_NAME, f.getPath());
		FileBasedAcl acl = new FileBasedAcl();
		acl.initialize("reloadTest");
		assertNotNull(acl.getPrincipal("tony"));
		assertNull(acl.getPrincipal("jose"));

		write(f, "tony , secret , READ\njose , other , READ|WRITE\n", t + 2000);
		assertTrue(acl.reloadNow());
		assertNotNull(acl.getPrincipal("jose"));
		assertTrue(acl.getPrincipal("jose").authenticate("other".getBytes(StandardCharsets.UTF_8)));
		assertFalse(acl.reloadNow(), "unchanged");

		// checked by the lookups themselves, at most every reloadSeconds
		System.setProperty(FileBasedAcl.PROP_RELOAD_SECONDS, "0");
		write(f, "jose , other , READ\n", t + 4000);
		assertNotNull(acl.getPrincipal("tony"), "0: never checked");
		assertTrue(acl.reloadNow());
		assertNull(acl.getPrincipal("tony"), "removed");
		assertEquals("jose", acl.getPrincipal("jose").getName());
	}

	@Test
	public void anUnreadableFileKeepsTheUsers() throws Exception {
		File f = new File(dir, "users.txt");
		long t = System.currentTimeMillis() - 60000;
		write(f, "tony , secret , READ\n", t);
		System.setProperty("reloadTest." + FileBasedAcl.PROP_FILE_NAME, f.getPath());
		FileBasedAcl acl = new FileBasedAcl();
		acl.initialize("reloadTest");
		assertTrue(f.delete());
		assertFalse(acl.reloadNow());
		assertNotNull(acl.getPrincipal("tony"), "the users read before stay");
	}
}
