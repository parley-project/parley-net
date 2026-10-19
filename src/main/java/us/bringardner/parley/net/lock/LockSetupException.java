package us.bringardner.parley.net.lock;

import java.io.IOException;

/**
 * A lock domain can't be set up: no provider can keep its locks with the sharing asked for, the
 * configured one would be unsafe or can't work there, or other servers keep the store's locks
 * another way.
 * @since 1.1.0
 */
public class LockSetupException extends IOException {
	private static final long serialVersionUID = 1L;

	/** @param message why */
	public LockSetupException(String message) {
		super(message);
	}
}
