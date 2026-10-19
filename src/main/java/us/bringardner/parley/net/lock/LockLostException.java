package us.bringardner.parley.net.lock;

import java.io.IOException;

/**
 * A lock is no longer held: it was released, or its lease ran out or was taken over by another
 * server. Work done under it must not be committed.
 * @since 1.1.0
 */
public class LockLostException extends IOException {
	private static final long serialVersionUID = 1L;

	/** @param message which lock, and why */
	public LockLostException(String message) {
		super(message);
	}
}
