package us.bringardner.parley.net.lock.spi;

import java.time.Duration;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.Sharing;

/**
 * What a {@link LockProvider} is given to open a {@link LockService} for a lock domain.
 * @since 1.1.0
 */
public final class LockContext {

	private final String domain;
	private final FileSource lockDirectory;
	private final FileSourceCapabilities capabilities;
	private final Sharing sharing;
	private final String ownerId;
	private final Duration lease;
	private final Duration renew;

	/**
	 * @param domain the lock domain's name
	 * @param lockDirectory where the service keeps its locks (it exists)
	 * @param capabilities what the store that holds them can guarantee
	 * @param sharing how many servers use it
	 * @param ownerId who this JVM is, as other servers see it
	 * @param lease how long a lease lasts, for services that use leases
	 * @param renew how often a lease is renewed
	 */
	public LockContext(String domain, FileSource lockDirectory, FileSourceCapabilities capabilities, Sharing sharing,
			String ownerId, Duration lease, Duration renew) {
		this.domain = domain;
		this.lockDirectory = lockDirectory;
		this.capabilities = capabilities;
		this.sharing = sharing;
		this.ownerId = ownerId;
		this.lease = lease;
		this.renew = renew;
	}

	/** @return the lock domain's name */
	public String domain() {
		return domain;
	}

	/** @return the directory the service keeps its locks in */
	public FileSource lockDirectory() {
		return lockDirectory;
	}

	/** @return what that store can guarantee */
	public FileSourceCapabilities capabilities() {
		return capabilities;
	}

	/** @return how many servers use it, and where */
	public Sharing sharing() {
		return sharing;
	}

	/** @return this JVM, as other servers see it */
	public String ownerId() {
		return ownerId;
	}

	/** @return how long a lease lasts */
	public Duration lease() {
		return lease;
	}

	/** @return how often a lease is renewed */
	public Duration renew() {
		return renew;
	}
}
