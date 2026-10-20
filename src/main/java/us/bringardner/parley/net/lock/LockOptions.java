package us.bringardner.parley.net.lock;

import java.time.Duration;
import java.util.Objects;

import us.bringardner.parley.files.FileSource;

/**
 * How {@link Locks} and its {@link LockDomain}s work. Immutable: each {@code with} method returns a
 * changed copy.
 * <pre>
 * LockOptions o = LockOptions.sharing(Sharing.CLUSTER).withTimeout(Duration.ofSeconds(5));
 * </pre>
 * Two settings can come from system properties, so a deployment can change them without code:
 * {@value #PROVIDER_PROPERTY} (the provider; default {@code auto}) and {@value #ALLOW_UNSAFE_PROPERTY}
 * ({@code true} to allow a provider whose locks wouldn't reach every server).
 * @since 1.1.0
 */
public final class LockOptions {

	/** System property: the provider when options don't name one ({@code auto}, {@code region}, {@code lease}, an id or a class). */
	public static final String PROVIDER_PROPERTY = "parley.net.lock.provider";
	/** System property: {@code true} to allow an UNSAFE provider. */
	public static final String ALLOW_UNSAFE_PROPERTY = "parley.net.lock.allowUnsafe";
	/** The provider chosen from the store's capabilities. */
	public static final String AUTO = "auto";

	private final Sharing sharing;
	private final String provider;
	private final boolean allowUnsafe;
	private final Duration timeout;
	private final boolean reentrant;
	private final Duration lease;
	private final Duration renew;
	private final String ownerId;
	private final FileSource coordinationStore;

	private LockOptions(Sharing sharing, String provider, boolean allowUnsafe, Duration timeout, boolean reentrant,
			Duration lease, Duration renew, String ownerId, FileSource coordinationStore) {
		this.sharing = Objects.requireNonNull(sharing, "sharing");
		this.provider = Objects.requireNonNull(provider, "provider").trim();
		if( this.provider.isEmpty() ) {
			throw new IllegalArgumentException("A provider can't be blank");
		}
		this.allowUnsafe = allowUnsafe;
		this.timeout = positive(timeout, "timeout");
		this.reentrant = reentrant;
		this.lease = positive(lease, "lease");
		this.renew = positive(renew, "renew");
		if( renew.multipliedBy(3).compareTo(lease) > 0 ) {
			// a holder stops trusting its lease a renew interval before it runs out (see the lease
			// provider), so it needs room for at least one renewal before then, and a missed one
			throw new IllegalArgumentException("The renew interval (" + renew + ") must be at most a third of the lease (" + lease + ")");
		}
		this.ownerId = ownerId;
		this.coordinationStore = coordinationStore;
	}

	private static Duration positive(Duration d, String what) {
		Objects.requireNonNull(d, what);
		if( d.isNegative() || d.isZero() ) {
			throw new IllegalArgumentException(what + " must be positive: " + d);
		}
		return d;
	}

	/**
	 * The defaults for a sharing: the provider from {@value #PROVIDER_PROPERTY} or {@code auto},
	 * unsafe providers refused unless {@value #ALLOW_UNSAFE_PROPERTY} is {@code true}, a 30 s
	 * timeout, reentrant locks, 30 s leases renewed every 10 s, each domain's locks in its own store.
	 * @param sharing how many servers use the stores, and where
	 * @return the options
	 */
	public static LockOptions sharing(Sharing sharing) {
		String p = System.getProperty(PROVIDER_PROPERTY);
		return new LockOptions(sharing, p == null || p.isBlank() ? AUTO : p, Boolean.getBoolean(ALLOW_UNSAFE_PROPERTY),
				Duration.ofSeconds(30), true, Duration.ofSeconds(30), Duration.ofSeconds(10), null, null);
	}

	/** @return how many servers use the stores */
	public Sharing sharing() {
		return sharing;
	}

	/** @return the provider: {@code auto}, a provider's id, or a class name */
	public String provider() {
		return provider;
	}

	/** @return whether a provider whose locks wouldn't reach every server is allowed */
	public boolean allowUnsafe() {
		return allowUnsafe;
	}

	/** @return how long a request waits unless it says otherwise */
	public Duration timeout() {
		return timeout;
	}

	/** @return whether locks are reentrant unless a request says otherwise */
	public boolean reentrant() {
		return reentrant;
	}

	/** @return how long a lease lasts without being renewed */
	public Duration lease() {
		return lease;
	}

	/** @return how often a lease is renewed */
	public Duration renew() {
		return renew;
	}

	/** @return who this JVM is, as other servers see it; null for one made up when Locks opens */
	public String ownerId() {
		return ownerId;
	}

	/** @return the one store every domain keeps its locks in, or null: each in its own */
	public FileSource coordinationStore() {
		return coordinationStore;
	}

	/** @param s how many servers use the stores */
	public LockOptions withSharing(Sharing s) {
		return new LockOptions(s, provider, allowUnsafe, timeout, reentrant, lease, renew, ownerId, coordinationStore);
	}

	/** @param p {@code auto}, a provider's id ({@code region}, {@code lease}, ...) or a LockProvider class name */
	public LockOptions withProvider(String p) {
		return new LockOptions(sharing, p, allowUnsafe, timeout, reentrant, lease, renew, ownerId, coordinationStore);
	}

	/** @param b true to allow a provider whose locks wouldn't reach every server (you know better) */
	public LockOptions withAllowUnsafe(boolean b) {
		return new LockOptions(sharing, provider, b, timeout, reentrant, lease, renew, ownerId, coordinationStore);
	}

	/** @param t how long requests wait unless they say otherwise */
	public LockOptions withTimeout(Duration t) {
		return new LockOptions(sharing, provider, allowUnsafe, t, reentrant, lease, renew, ownerId, coordinationStore);
	}

	/** @param r whether locks are reentrant unless a request says otherwise */
	public LockOptions withReentrant(boolean r) {
		return new LockOptions(sharing, provider, allowUnsafe, timeout, r, lease, renew, ownerId, coordinationStore);
	}

	/**
	 * @param lease how long a lease lasts without being renewed
	 * @param renew how often it is renewed; at most a third of the lease
	 */
	public LockOptions withLease(Duration lease, Duration renew) {
		return new LockOptions(sharing, provider, allowUnsafe, timeout, reentrant, lease, renew, ownerId, coordinationStore);
	}

	/** @param id who this JVM is, as other servers see it (the default names host and process) */
	public LockOptions withOwnerId(String id) {
		return new LockOptions(sharing, provider, allowUnsafe, timeout, reentrant, lease, renew, id, coordinationStore);
	}

	/**
	 * @param store a store every server reaches (a database, say) that keeps every domain's locks,
	 *        wherever the domains' data is; null for each domain's locks in its own store
	 */
	public LockOptions withCoordinationStore(FileSource store) {
		return new LockOptions(sharing, provider, allowUnsafe, timeout, reentrant, lease, renew, ownerId, store);
	}

	@Override
	public String toString() {
		return "LockOptions[sharing=" + sharing + ", provider=" + provider + (allowUnsafe ? " (unsafe allowed)" : "")
				+ ", timeout=" + timeout + ", reentrant=" + reentrant + ", lease=" + lease + "/" + renew
				+ (coordinationStore != null ? ", coordination store " + coordinationStore.getAbsolutePath() : "") + "]";
	}
}
