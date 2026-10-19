package us.bringardner.parley.net.lock;

import java.io.IOException;

import us.bringardner.parley.net.lock.spi.LockHandle;

/**
 * One holding of a name by one thread (see {@link Locks}). Close it to let go: the name is free
 * when every holding of it in the JVM is closed. Closing twice does nothing more.
 * @since 1.1.0
 */
public final class NamedLock implements AutoCloseable {

	private final Locks locks;
	private final LockDomain domain;
	private final Locks.Entry entry;
	final Thread thread;
	private final Mode mode;
	private boolean closed;

	NamedLock(Locks locks, LockDomain domain, Locks.Entry entry, Thread thread, Mode mode) {
		this.locks = locks;
		this.domain = domain;
		this.entry = entry;
		this.thread = thread;
		this.mode = mode;
	}

	/** @return the domain */
	public LockDomain domain() {
		return domain;
	}

	/** @return the name */
	public String name() {
		return entry.name;
	}

	/** @return how this thread holds it (exclusive if it held it exclusive when it asked again) */
	public Mode mode() {
		return mode;
	}

	/** @return whether it is still held, as far as this JVM knows without asking the store */
	public boolean isValid() {
		synchronized (entry) {
			return !closed && entry.handle != null && entry.handle.isValid();
		}
	}

	/**
	 * Check with the store (where locks are leases) that it is still held: call it just before
	 * committing work done under it.
	 * @throws LockLostException if it was released, or its lease ran out or was taken over
	 * @throws IOException if the store can't be asked
	 */
	public void checkValid() throws IOException {
		LockHandle h;
		synchronized (entry) {
			if( closed ) {
				throw new LockLostException("The lock on " + domain.name() + ":" + entry.name + " was released");
			}
			h = entry.handle;
		}
		if( h == null ) {
			throw new LockLostException("The lock on " + domain.name() + ":" + entry.name + " is no longer held");
		}
		h.verify();
	}

	/**
	 * Let this holding go.
	 * @throws IllegalMonitorStateException if called by a thread other than the one that took it
	 */
	@Override
	public void close() {
		if( Thread.currentThread() != thread ) {
			throw new IllegalMonitorStateException("The lock on " + domain.name() + ":" + entry.name + " is held by "
					+ thread.getName() + "; only it can let it go");
		}
		closeFromAnyThread();
	}

	/** Let go from whatever thread: for holdings owned by the framework (the store claim). */
	void closeFromAnyThread() {
		synchronized (entry) {
			if( closed ) {
				return;
			}
			closed = true;
			locks.release(entry, this);
		}
	}

	@Override
	public String toString() {
		return (mode == Mode.SHARED ? "shared" : "exclusive") + " lock on " + domain.name() + ":" + entry.name
				+ (closed ? " (released)" : "");
	}
}
