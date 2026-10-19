package us.bringardner.parley.net.lock;

/**
 * How many servers use a store, and where they run. With the store's capabilities it decides how a
 * {@link LockDomain} keeps its locks (see {@link Locks}).
 * @since 1.1.0
 */
public enum Sharing {
	/**
	 * One server uses the store. Its locks only need to reach its own threads, and the
	 * {@link StoreClaim} keeps a second server out.
	 */
	OFF,
	/** Several servers on one machine use the store. */
	HOST,
	/** Several servers, on any machines, use the store. */
	CLUSTER;

	/**
	 * Parse a setting such as {@code parley.mail.sharedStore}: {@code off}, {@code host} or
	 * {@code cluster}, in any case; {@code false} and {@code true} are read as {@code off} and
	 * {@code cluster}.
	 * @param value the setting; null or blank is {@code off}
	 * @return the sharing
	 * @throws IllegalArgumentException for anything else
	 */
	public static Sharing parse(String value) {
		if( value == null || value.isBlank() ) {
			return OFF;
		}
		switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
		case "off":
		case "false":
			return OFF;
		case "host":
			return HOST;
		case "cluster":
		case "true":
			return CLUSTER;
		default:
			throw new IllegalArgumentException("Not a sharing setting (off, host or cluster): " + value);
		}
	}
}
