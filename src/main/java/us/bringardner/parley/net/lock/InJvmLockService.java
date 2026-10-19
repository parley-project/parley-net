package us.bringardner.parley.net.lock;

import us.bringardner.parley.net.lock.spi.LockHandle;
import us.bringardner.parley.net.lock.spi.LockService;

/** {@link Sharing#OFF}: names need reach only this JVM, as the store claim keeps other servers out. */
final class InJvmLockService implements LockService {

	private static final LockHandle HELD = () -> true;

	@Override
	public LockHandle tryAcquire(String name, Mode mode) {
		return HELD;
	}

	@Override
	public void release(LockHandle h) {
		// nothing outside the JVM
	}

	@Override
	public void close() {
	}

	@Override
	public String toString() {
		return "this JVM only";
	}
}
