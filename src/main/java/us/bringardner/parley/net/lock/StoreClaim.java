package us.bringardner.parley.net.lock;

import java.util.function.BooleanSupplier;

/**
 * A server's claim on its store, from {@link LockSpace#claimStore(String)}: held while the server
 * runs, and closed when it stops.
 * @since 1.1.0
 */
public final class StoreClaim implements AutoCloseable {

	private final String serverId;
	private final Sharing sharing;
	private final Runnable release;
	private final BooleanSupplier valid;
	private boolean closed;

	StoreClaim(String serverId, Sharing sharing, Runnable release, BooleanSupplier valid) {
		this.serverId = serverId;
		this.sharing = sharing;
		this.release = release;
		this.valid = valid;
	}

	/** @return the server's id */
	public String serverId() {
		return serverId;
	}

	/** @return whether it was claimed alone ({@link Sharing#OFF}) or shared */
	public Sharing sharing() {
		return sharing;
	}

	/** @return whether the claim is still held (a lease can be lost if it can't be renewed) */
	public boolean isValid() {
		synchronized (this) {
			return !closed && valid.getAsBoolean();
		}
	}

	/** Give the claim up. Closing it twice does nothing more. */
	@Override
	public synchronized void close() {
		if( !closed ) {
			closed = true;
			release.run();
		}
	}
}
