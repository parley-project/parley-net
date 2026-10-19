package us.bringardner.parley.net.lock.spi;

import java.io.IOException;

import us.bringardner.parley.net.lock.Mode;

/**
 * Locks on names that reach every server using one store, opened by a {@link LockProvider} for a
 * lock domain. The framework ({@link us.bringardner.parley.net.lock.Locks}) does everything among
 * the threads of this JVM (waiting, fairness, timeouts, reentrancy) and asks the service once for
 * each holding of a name by this JVM, never twice at once for one name: a service only answers
 * "can this JVM have this name now?".
 * @since 1.1.0
 */
public interface LockService extends AutoCloseable {

	/**
	 * Take a name now.
	 * @param name the name
	 * @param mode shared or exclusive; a service that can't share between servers may hold a shared
	 *        request exclusive (stricter, never weaker)
	 * @return the holding, or null if another server holds it (or it can't tell yet)
	 * @throws IOException if the store can't be asked
	 */
	LockHandle tryAcquire(String name, Mode mode) throws IOException;

	/** Give a holding back. Never throws: a failure is logged. */
	void release(LockHandle h);

	/**
	 * This JVM stopped waiting for a name it asked for exclusive (a timeout, an interrupt): drop
	 * anything its tries left behind to keep others out while it waited.
	 * @param name the name
	 */
	default void cancel(String name) {
	}

	/** @return the longest a waiter sleeps between tries (ms) */
	default long pollCapMillis() {
		return 50;
	}

	/**
	 * @return how long a server should wait before deciding another server's claim on the store is
	 *         live (ms): zero where a dead server's locks go with it, a lease or so where they expire
	 */
	default long claimWaitMillis() {
		return 0;
	}

	/** Stop. The framework releases what it holds first. */
	@Override
	void close();
}
