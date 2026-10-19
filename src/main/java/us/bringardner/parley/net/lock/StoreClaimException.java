package us.bringardner.parley.net.lock;

import java.io.IOException;

/**
 * A server can't claim its store: another server holds it in a way this one's sharing doesn't
 * allow, or the store can't be shared as asked.
 * @since 1.1.0
 */
public class StoreClaimException extends IOException {
	private static final long serialVersionUID = 1L;

	/** @param message why */
	public StoreClaimException(String message) {
		super(message);
	}
}
