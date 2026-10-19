package us.bringardner.parley.net.lock;

import java.io.IOException;

/**
 * A lock stayed busy for as long as the request was willing to wait.
 * @since 1.1.0
 */
public class LockTimeoutException extends IOException {
	private static final long serialVersionUID = 1L;

	/** @param message what was busy */
	public LockTimeoutException(String message) {
		super(message);
	}
}
