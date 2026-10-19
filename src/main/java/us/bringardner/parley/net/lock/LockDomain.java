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
	private NamedLock serverId;
	private int claimCount;

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
	 * orders). Every server in this JVM claims through this domain: the store is claimed once, when
	 * the first asks, and given up when the last claim is closed. Where a dead server's claim
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
		if( claimCount == 0 ) {
			Sharing sharing = options.sharing();
			Mode mode = sharing == Sharing.OFF ? Mode.EXCLUSIVE : Mode.SHARED;
			long wait = service.claimWaitMillis() * 1_000_000;
			NamedLock c = claimLock(Locks.STORE, mode, wait);
			if( c == null ) {
				throw new StoreClaimException(sharing == Sharing.OFF
						? "The store " + root.getAbsolutePath() + " is in use by another server"
						: "The store " + root.getAbsolutePath() + " is claimed by a server that doesn't share it");
			}
			if( sharing != Sharing.OFF ) {
				NamedLock id = claimLock(Locks.SERVER + serverId, Mode.EXCLUSIVE, wait);
				if( id == null ) {
					c.closeFromAnyThread();
					throw new StoreClaimException("Another running server of " + root.getAbsolutePath() + " has the id " + serverId);
				}
				serverId(id);
			}
			claim = c;
		}
		claimCount++;
		return new StoreClaim(serverId, options.sharing(), this::releaseClaim, this::claimValid);
	}

	private void serverId(NamedLock id) {
		this.serverId = id;
	}

	/** @return the holding, or null if it stayed busy for the wait */
	private NamedLock claimLock(String n, Mode mode, long waitNanos) throws IOException {
		try {
			return locks.acquire(this, n, name + "\u0000" + n, prefix + n, service, mode, waitNanos == 0 ? -1 : waitNanos, false);
		} catch (LockTimeoutException busy) {
			return null;
		}
	}

	private synchronized boolean claimValid() {
		return claimCount > 0 && claim.isValid() && (serverId == null || serverId.isValid());
	}

	private synchronized void releaseClaim() {
		if( --claimCount == 0 ) {
			if( serverId != null ) {
				serverId.closeFromAnyThread();
				serverId = null;
			}
			claim.closeFromAnyThread();
			claim = null;
		}
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
