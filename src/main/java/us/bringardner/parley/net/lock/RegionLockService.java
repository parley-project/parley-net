package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.lock.FileSourceLock;
import us.bringardner.parley.net.lock.spi.LockHandle;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * Locks as FileSource region locks on one lock file: each name is a one-byte region at a position
 * from a 63-bit hash of the name. However many names are locked, there is one file, and two names
 * share a region (and so wait for each other) only if their hashes collide, which in practice they
 * don't. The locks reach as far as the store's lock scope.
 */
final class RegionLockService implements LockService {

	private static final Logger LOG = Logger.getLogger(RegionLockService.class.getName());
	static final String FILE = "regions";

	private final FileSource file;

	RegionLockService(FileSource lockDir) throws IOException {
		file = lockDir.getChild(FILE);
		if( !file.exists() && !file.createNewFile() && !file.exists() ) {
			throw new IOException("Can't create the lock file " + file.getAbsolutePath());
		}
	}

	/** @return the region's position: 0 to Long.MAX_VALUE - 1, so a one-byte region fits */
	static long positionOf(String name) {
		try {
			byte[] h = MessageDigest.getInstance("SHA-256").digest(name.getBytes(StandardCharsets.UTF_8));
			long v = 0;
			for (int i = 0; i < 8; i++) {
				v = (v << 8) | (h[i] & 0xFF);
			}
			v &= Long.MAX_VALUE;
			return v == Long.MAX_VALUE ? v - 1 : v;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is required of every JVM", e);
		}
	}

	@Override
	public LockHandle tryAcquire(String name, Mode mode) throws IOException {
		FileSourceLock l;
		try {
			l = file.tryLock(positionOf(name), 1, mode == Mode.SHARED);
		} catch (OverlappingFileLockException collision) {
			// this JVM holds the region for another name whose hash collides: busy until it lets go
			return null;
		}
		return l == null ? null : new RegionHandle(l);
	}

	@Override
	public void release(LockHandle h) {
		try {
			((RegionHandle) h).lock.release();
		} catch (IOException | RuntimeException e) {
			LOG.log(Level.WARNING, "Releasing a lock on " + file.getAbsolutePath(), e);
		}
	}

	@Override
	public void close() {
	}

	@Override
	public String toString() {
		return "region locks on " + file.getAbsolutePath();
	}

	private static final class RegionHandle implements LockHandle {
		final FileSourceLock lock;

		RegionHandle(FileSourceLock lock) {
			this.lock = lock;
		}

		@Override
		public boolean isValid() {
			return lock.isValid();
		}
	}
}
