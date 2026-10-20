package us.bringardner.parley.net.lock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/** StoreLocks: one domain per root for this JVM's file servers, nested roots sharing one. */
public class StoreLocksTest {

	private FileSource top;

	@BeforeEach
	public void setUp() throws Exception {
		File d = Files.createTempDirectory("store-locks").toFile();
		d.deleteOnExit();
		top = FileSourceFactory.getDefaultFactory().createFileSource(d.getCanonicalPath());
	}

	private FileSource dir(FileSource parent, String name) throws Exception {
		FileSource f = parent.getChild(name);
		f.mkdirs();
		return f;
	}

	@Test
	public void oneDomainPerRootRefcounted() throws Exception {
		StoreLocks s = StoreLocks.get();
		LockDomain a = s.acquire(top, Sharing.OFF);
		LockDomain b = s.acquire(top, Sharing.OFF);
		assertSame(a, b, "one domain for the root");
		s.release(a);
		assertFalse(a.isClosed(), "another user still has it");
		s.release(b);
		assertTrue(a.isClosed(), "the last one closes it");
		assertNull(s.domainOf(top));
	}

	@Test
	public void aRootInsideARegisteredOneSharesItsDomain() throws Exception {
		StoreLocks s = StoreLocks.get();
		FileSource inner = dir(top, "tony");
		LockDomain outer = s.acquire(top, Sharing.OFF);
		try {
			LockDomain d = s.acquire(inner, Sharing.OFF);
			assertSame(outer, d, "the outer root's domain");
			assertEquals("file/tony/a.txt", StoreLocks.fileLockName(d, inner.getChild("a.txt")),
					"named from the domain's root, whichever server asks");
			s.release(d);
		} finally {
			s.release(outer);
		}
	}

	@Test
	public void theDeepestRootHoldsTheFile() throws Exception {
		StoreLocks s = StoreLocks.get();
		FileSource inner = dir(top, "tony");
		LockDomain in = s.acquire(inner, Sharing.OFF);
		LockDomain out = s.acquire(top, Sharing.OFF);
		try {
			assertNotSame(in, out, "registered first, the inner root has its own");
			assertSame(in, s.domainOf(inner.getChild("a.txt")));
			assertSame(out, s.domainOf(top.getChild("b.txt")));
			assertEquals("file/a.txt", StoreLocks.fileLockName(in, inner.getChild("a.txt")));
			assertEquals("file/", StoreLocks.fileLockName(out, top));
			assertThrows(IllegalArgumentException.class, () -> StoreLocks.fileLockName(in, top.getChild("b.txt")));
		} finally {
			s.release(in);
			s.release(out);
		}
	}

	@Test
	public void aFileBeingLockedKeepsItsDomainOpen() throws Exception {
		StoreLocks s = StoreLocks.get();
		LockDomain d = s.acquire(top, Sharing.OFF);
		LockDomain held = s.acquireFor(top.getChild("x.txt"));
		assertSame(d, held);
		s.release(d); // the server that registered it stops
		assertFalse(held.isClosed(), "kept for the lock being taken");
		try (NamedLock l = held.lock(StoreLocks.fileLockName(held, top.getChild("x.txt")), Mode.EXCLUSIVE, java.time.Duration.ofSeconds(5))) {
			assertTrue(l.isValid());
		}
		s.release(held);
		assertTrue(held.isClosed());
		assertNull(s.acquireFor(top.getChild("x.txt")), "nothing registered holds it now");
	}

	/** A link in a root that leads outside it is locked by its own path in the root. */
	@Test
	public void aLinkLeadingOutsideIsLockedByItsOwnPath() throws Exception {
		File outside = Files.createTempDirectory("store-locks-outside").toFile();
		outside.deleteOnExit();
		File target = new File(outside, "t.txt");
		Files.write(target.toPath(), new byte[] {1});
		try {
			Files.createSymbolicLink(new File(top.getAbsolutePath(), "link.txt").toPath(), target.toPath());
		} catch (UnsupportedOperationException | java.io.IOException e) {
			org.junit.jupiter.api.Assumptions.assumeTrue(false, "no symbolic links here: " + e);
		}
		StoreLocks s = StoreLocks.get();
		LockDomain d = s.acquire(top, Sharing.OFF);
		try {
			FileSource link = top.getChild("link.txt");
			LockDomain held = s.acquireFor(link);
			assertSame(d, held);
			assertEquals("file/link.txt", StoreLocks.fileLockName(d, link));
			s.release(held);
		} finally {
			s.release(d);
		}
	}

	@Test
	public void theLockDirectoryIsKnown() throws Exception {
		StoreLocks s = StoreLocks.get();
		LockDomain d = s.acquire(top, Sharing.OFF);
		try {
			assertTrue(s.isLockFile(top.getChild(Locks.DIRECTORY)));
			assertTrue(s.isLockFile(top.getChild(Locks.DIRECTORY).getChild("regions")));
			assertFalse(s.isLockFile(top.getChild("data.txt")));
			assertFalse(s.isLockFile(top.getChild(Locks.DIRECTORY + "x")));
		} finally {
			s.release(d);
		}
	}

	@Test
	public void serverIds() {
		String before = System.getProperty("parley.test.serverId");
		try {
			System.clearProperty("parley.test.serverId");
			assertTrue(StoreLocks.serverId("parley.test.serverId", "ftp", 2121).endsWith("-ftp-2121"));
			assertTrue(StoreLocks.serverId("parley.test.serverId", "sftp", 0).contains("-sftp-pid"));
			System.setProperty("parley.test.serverId", "my server/1");
			assertEquals("my_server_1", StoreLocks.serverId("parley.test.serverId", "ftp", 21));
			assertNotNull(StoreLocks.serverId(null, "x", 1));
		} finally {
			if( before == null ) {
				System.clearProperty("parley.test.serverId");
			} else {
				System.setProperty("parley.test.serverId", before);
			}
		}
	}
}
