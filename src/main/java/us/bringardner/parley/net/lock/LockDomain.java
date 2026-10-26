package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.spi.LockProvider;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * One store's locks, registered with {@link Locks#domain}: names within it, kept by the provider
 * chosen for the store, and the store claim.
 * @since 1.1.0
 */
public final class LockDomain {

	private final Locks locks;
	private final String name;
	private final FileSource root;
	private final LockOptions options;
	private final LockProvider provider;
	private final FileSourceCapabilities capabilities;
	private final LockService names;
	private final LockService service;
	/** Put before names given to the service (the domain's, in a coordination store). */
	private final String prefix;
	/** The store claim, shared by every StoreClaim this domain gave out; guarded by this. */
	private NamedLock claim;
	/** The ids of the servers of this JVM that claim the store, and their locks (null: sharing off); guarded by this. */
	private final java.util.Map<String, NamedLock> serverIds = new java.util.HashMap<>();
	private int claimCount;
	private volatile boolean closed;

	LockDomain(Locks locks, String name, FileSource root, LockOptions options, LockProvider provider,
			FileSourceCapabilities capabilities, LockService names, LockService service, String prefix) {
		this.locks = locks;
		this.name = name;
		this.root = root;
		this.options = options;
		this.provider = provider;
		this.capabilities = capabilities;
		this.names = names;
		this.service = service;
		this.prefix = prefix;
	}

	/** @return its name */
	public String name() {
		return name;
	}

	/** @return the store's root */
	public FileSource root() {
		return root;
	}

	/** @return its options */
	public LockOptions options() {
		return options;
	}

	/** @return how many servers use the store */
	public Sharing sharing() {
		return options.sharing();
	}

	/** @return the provider that keeps its locks between servers */
	public LockProvider provider() {
		return provider;
	}

	/** @return the capabilities of the store that keeps its locks */
	public FileSourceCapabilities capabilities() {
		return capabilities;
	}

	/** @return how its locks are kept, in words (for logs) */
	public String describe() {
		return name + ": " + (options.sharing() == Sharing.OFF ? "names in this JVM, claim by " : "") + provider.id() + " ("
				+ service + ")";
	}

	/**
	 * @param n a name in this domain
	 * @return it, for {@link Locks#lockAll}
	 */
	public LockName name(String n) {
		checkName(n);
		return new LockName(this, n);
	}

	// ------------------------------------------------------------------ taking locks

	/**
	 * Take a name, waiting up to a timeout. Reentrant unless the options say otherwise.
	 * @param n what to lock; not empty, not starting with {@code .parley/}
	 * @param mode shared or exclusive
	 * @param timeout how long to wait
	 * @return the holding; close it to let go
	 * @throws LockTimeoutException if it stayed busy for the whole timeout
	 * @throws java.io.InterruptedIOException if the thread is interrupted while it waits
	 * @throws IOException if the store can't be asked
	 */
	public NamedLock lock(String n, Mode mode, Duration timeout) throws IOException {
		return request(n).mode(mode).timeout(timeout).acquire();
	}

	/**
	 * Take a name now, or return null if it is busy.
	 * @param n what to lock
	 * @param mode shared or exclusive
	 * @return the holding, or null
	 * @throws IOException if the store can't be asked
	 */
	public NamedLock tryLock(String n, Mode mode) throws IOException {
		return request(n).mode(mode).tryAcquire();
	}

	/**
	 * A request with every option: mode, timeout, reentrancy.
	 * @param n what to lock
	 * @return the request (exclusive, with the options' timeout and reentrancy, until changed)
	 */
	public LockRequest request(String n) {
		checkName(n);
		return new LockRequest(this, n);
	}

	/**
	 * Take several names in this domain in one order (see {@link Locks#lockAll}).
	 * @param ns what to lock
	 * @param mode shared or exclusive
	 * @param timeout how long to wait for all of them
	 * @return the holdings
	 * @throws IOException as {@link Locks#lockAll} does
	 */
	public LockGroup lockAll(Collection<String> ns, Mode mode, Duration timeout) throws IOException {
		List<LockName> list = new ArrayList<>();
		for (String n : ns) {
			list.add(name(n));
		}
		return locks.lockAll(list, mode, timeout);
	}

	NamedLock acquire(String n, Mode mode, long timeoutNanos, boolean reentrant) throws IOException {
		return locks.acquire(this, n, name + "\u0000" + n, prefix + n, names, mode, timeoutNanos, reentrant);
	}

	private static void checkName(String n) {
		Objects.requireNonNull(n, "name");
		if( n.isEmpty() ) {
			throw new IllegalArgumentException("A lock's name can't be empty");
		}
		if( n.startsWith(Locks.RESERVED) ) {
			throw new IllegalArgumentException("Names starting " + Locks.RESERVED + " are kept for the framework: " + n);
		}
	}

	// ------------------------------------------------------------------ the store claim

	/**
	 * Claim the store for this server, for as long as it runs: {@link Sharing#OFF} claims it alone,
	 * so a second server (another JVM) is refused; {@link Sharing#HOST} and {@link Sharing#CLUSTER}
	 * share it with servers that share it too, and refuse one that claims it alone (in both
	 * orders). A server of this JVM gets the answer a server in another process would: with
	 * sharing off a second one is refused, and sharing servers need different ids. The store's
	 * lock is taken once, when the first asks, and given up when the last claim is closed. Where a dead server's claim
	 * expires rather than going with it (leases), finding out takes up to a lease.
	 * @param serverId this server's name among those that share the store (letters, digits,
	 *        {@code . _ -}); two running sharing servers can't have the same one
	 * @return the claim; close it when the server stops
	 * @throws StoreClaimException if another server's claim doesn't allow this one
	 * @throws IOException if the store can't be asked
	 */
	public synchronized StoreClaim claimStore(String serverId) throws IOException {
		Objects.requireNonNull(serverId, "serverId");
		if( !serverId.matches("[A-Za-z0-9._-]+") ) {
			throw new IllegalArgumentException("A server id is letters, digits, '.', '_' and '-': " + serverId);
		}
		locks.checkOpen();
		Sharing sharing = options.sharing();
		long wait = service.claimWaitMillis() * 1_000_000;
		if( claimCount > 0 && sharing == Sharing.OFF ) {
			// a server of this JVM has the store alone: the answer another process would get
			throw new StoreClaimException("The store " + root.getAbsolutePath() + " is in use by another server");
		}
		if( serverIds.containsKey(serverId) ) {
			throw new StoreClaimException("Another running server of " + root.getAbsolutePath() + " has the id " + serverId);
		}
		NamedLock c = claim;
		boolean madeClaim = false;
		if( claimCount == 0 ) {
			Mode mode = sharing == Sharing.OFF ? Mode.EXCLUSIVE : Mode.SHARED;
			c = claimLock(Locks.STORE, mode, wait);
			if( c == null ) {
				throw new StoreClaimException(sharing == Sharing.OFF
						? "The store " + root.getAbsolutePath() + " is in use by another server"
						: "The store " + root.getAbsolutePath() + " is claimed by a server that doesn't share it");
			}
			madeClaim = true;
		}
		NamedLock id = null;
		if( sharing != Sharing.OFF ) {
			try {
				id = claimLock(Locks.SERVER + serverId, Mode.EXCLUSIVE, wait);
			} catch (IOException | RuntimeException | Error e) {
				if( madeClaim ) {
					c.closeFromAnyThread(); // interrupted, or the store failed: don't keep the store's lock
				}
				throw e;
			}
			if( id == null ) {
				if( madeClaim ) {
					c.closeFromAnyThread();
				}
				throw new StoreClaimException("Another running server of " + root.getAbsolutePath() + " has the id " + serverId);
			}
		}
		claim = c;
		serverIds.put(serverId, id);
		claimCount++;
		return new StoreClaim(serverId, sharing, () -> releaseClaim(serverId), () -> claimValid(serverId));
	}

	/** @return the holding, or null if it stayed busy for the wait */
	private NamedLock claimLock(String n, Mode mode, long waitNanos) throws IOException {
		try {
			return locks.acquire(this, n, name + "\u0000" + n, prefix + n, service, mode, waitNanos == 0 ? -1 : waitNanos, false);
		} catch (LockTimeoutException busy) {
			return null;
		}
	}

	private synchronized boolean claimValid(String serverId) {
		if( claimCount <= 0 || !serverIds.containsKey(serverId) || !claim.isValid() ) {
			return false;
		}
		NamedLock id = serverIds.get(serverId);
		return id == null || id.isValid();
	}

	private synchronized void releaseClaim(String serverId) {
		if( claimCount <= 0 || !serverIds.containsKey(serverId) ) {
			return; // given up already (the domain was closed)
		}
		NamedLock id = serverIds.remove(serverId);
		if( id != null ) {
			id.closeFromAnyThread();
		}
		if( --claimCount == 0 ) {
			claim.closeFromAnyThread();
			claim = null;
		}
	}

	/** Give up every claim (the domain is closed). */
	private synchronized void releaseAllClaims() {
		for( String id : new java.util.ArrayList<>(serverIds.keySet()) ) {
			releaseClaim(id);
		}
	}

	/**
	 * Unregister the domain: what this JVM holds in it is let go (holdings still open find their
	 * lock lost: {@link NamedLock#isValid()} is false and {@link NamedLock#checkValid()} throws),
	 * threads waiting for one of its names get an IOException, its services stop (leases are no
	 * longer renewed) and its name can be registered again. Closing twice does nothing more.
	 */
	public void close() {
		synchronized (this) {
			if( closed ) {
				return;
			}
			closed = true;
			releaseAllClaims();
		}
		locks.releaseAll(this);
		locks.remove(this);
		closeServices();
	}

	/** @return whether {@link #close()} was called */
	public boolean isClosed() {
		return closed;
	}

	void closeServices() {
		names.close();
		if( service != names ) {
			service.close();
		}
	}

	@Override
	public String toString() {
		return "LockDomain[" + describe() + "]";
	}
}
