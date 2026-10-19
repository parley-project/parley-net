package us.bringardner.parley.net.lock;

/**
 * How a {@link NamedLock} is held.
 * @since 1.1.0
 */
public enum Mode {
	/** Held by any number of holders at once, but by no exclusive holder. */
	SHARED,
	/** Held by one holder only. */
	EXCLUSIVE
}
