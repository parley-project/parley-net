package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;

/**
 * A lock request with every option (from {@link LockDomain#request(String)}):
 * <pre>
 * try (NamedLock l = queue.request("81").exclusive().timeout(Duration.ofSeconds(5)).reentrant(false).acquire()) {
 *     ...
 * }
 * </pre>
 * Exclusive, with the domain's timeout and reentrancy, until changed.
 * @since 1.1.0
 */
public final class LockRequest {

	private final LockDomain domain;
	private final String name;
	private Mode mode = Mode.EXCLUSIVE;
	private Duration timeout;
	private boolean reentrant;

	LockRequest(LockDomain domain, String name) {
		this.domain = domain;
		this.name = name;
		this.timeout = domain.options().timeout();
		this.reentrant = domain.options().reentrant();
	}

	/** @param m shared or exclusive */
	public LockRequest mode(Mode m) {
		this.mode = Objects.requireNonNull(m, "mode");
		return this;
	}

	/** Ask for it shared. */
	public LockRequest shared() {
		return mode(Mode.SHARED);
	}

	/** Ask for it exclusive. */
	public LockRequest exclusive() {
		return mode(Mode.EXCLUSIVE);
	}

	/** @param t how long {@link #acquire()} waits */
	public LockRequest timeout(Duration t) {
		Objects.requireNonNull(t, "timeout");
		if( t.isNegative() ) {
			throw new IllegalArgumentException("A timeout can't be negative: " + t);
		}
		this.timeout = t;
		return this;
	}

	/**
	 * @param r true: a thread that holds the name gets it again at once; false: asking again throws
	 *        IllegalStateException
	 */
	public LockRequest reentrant(boolean r) {
		this.reentrant = r;
		return this;
	}

	/**
	 * Take it, waiting up to the timeout.
	 * @return the holding
	 * @throws LockTimeoutException if it stayed busy for the whole timeout
	 * @throws java.io.InterruptedIOException if the thread is interrupted while it waits
	 * @throws IOException if the store can't be asked
	 */
	public NamedLock acquire() throws IOException {
		return domain.acquire(name, mode, timeout.toNanos(), reentrant);
	}

	/**
	 * Take it now, without waiting.
	 * @return the holding, or null if it is busy
	 * @throws IOException if the store can't be asked
	 */
	public NamedLock tryAcquire() throws IOException {
		return domain.acquire(name, mode, -1, reentrant);
	}
}
