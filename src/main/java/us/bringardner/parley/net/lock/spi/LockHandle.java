package us.bringardner.parley.net.lock.spi;

import java.io.IOException;

import us.bringardner.parley.net.lock.LockLostException;

/**
 * One holding of a name by one JVM, from {@link LockService#tryAcquire}.
 * @since 1.1.0
 */
public interface LockHandle {

	/** @return whether it is still held, as far as this JVM knows without asking the store */
	boolean isValid();

	/**
	 * Ask the store whether it is still held (a lease can be taken over).
	 * @throws LockLostException if it isn't
	 * @throws IOException if the store can't be asked
	 */
	default void verify() throws IOException {
		if( !isValid() ) {
			throw new LockLostException("The lock is no longer held");
		}
	}
}
