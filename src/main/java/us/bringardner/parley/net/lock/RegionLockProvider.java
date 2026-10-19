package us.bringardner.parley.net.lock;

import java.io.IOException;

import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.files.lock.LockScope;
import us.bringardner.parley.net.lock.spi.LockContext;
import us.bringardner.parley.net.lock.spi.LockProvider;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * The liberal way, id {@value #ID}: the store's own locks (FileSource region locks on one file,
 * a one-byte region per name). Fast, and a dead server's locks go with it, but only as far as the
 * store's lock scope reaches: SAFE when that covers the sharing (HOST scope for {@link Sharing#OFF}
 * and {@link Sharing#HOST}, CLUSTER for {@link Sharing#CLUSTER}), UNSAFE otherwise.
 * @since 1.1.0
 */
public final class RegionLockProvider implements LockProvider {

	/** Its id. */
	public static final String ID = "region";

	@Override
	public String id() {
		return ID;
	}

	@Override
	public Fit fit(FileSourceCapabilities c, Sharing sharing) {
		LockScope need = sharing == Sharing.CLUSTER ? LockScope.CLUSTER : LockScope.HOST;
		return c.lockScope().ordinal() >= need.ordinal() ? Fit.SAFE : Fit.UNSAFE;
	}

	@Override
	public String whyNot(FileSourceCapabilities c, Sharing sharing) {
		if( fit(c, sharing) == Fit.SAFE ) {
			return null;
		}
		return "the store's locks reach " + c.lockScope() + " only, and sharing " + sharing + " needs "
				+ (sharing == Sharing.CLUSTER ? "CLUSTER" : "HOST") + " (another server wouldn't see them)";
	}

	@Override
	public LockService open(LockContext context) throws IOException {
		return new RegionLockService(context.lockDirectory());
	}

	@Override
	public String toString() {
		return ID;
	}
}
