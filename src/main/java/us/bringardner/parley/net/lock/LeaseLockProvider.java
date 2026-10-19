package us.bringardner.parley.net.lock;

import java.io.IOException;

import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.spi.LockContext;
import us.bringardner.parley.net.lock.spi.LockProvider;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * The conservative way, id {@value #ID}: lease directories, which ask only for an atomic
 * {@code mkdir} ({@link FileSourceCapabilities#atomicMkdir()}), so they work where the store has
 * no locks of its own (FTP, SFTP, a local disk shared between machines). A dead server's leases
 * are taken over a lease after its last renewal, and a server paused for longer than its lease
 * can lose a lock (see {@link NamedLock#checkValid()}). Readers on several servers share a name
 * where the store applies its operations in one order
 * ({@link FileSourceCapabilities#orderedOperations()}); elsewhere they take turns.
 * @since 1.1.0
 */
public final class LeaseLockProvider implements LockProvider {

	/** Its id. */
	public static final String ID = "lease";

	@Override
	public String id() {
		return ID;
	}

	@Override
	public Fit fit(FileSourceCapabilities c, Sharing sharing) {
		return c.atomicMkdir() ? Fit.SAFE : Fit.UNSUPPORTED;
	}

	@Override
	public String whyNot(FileSourceCapabilities c, Sharing sharing) {
		return c.atomicMkdir() ? null : "the store's mkdir isn't atomic, and leases need it to be";
	}

	@Override
	public LockService open(LockContext context) throws IOException {
		return new LeaseLockService(context.lockDirectory(), context.ownerId(), context.lease(), context.renew(),
				context.capabilities().orderedOperations());
	}

	@Override
	public String toString() {
		return ID;
	}
}
