package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceCapabilities;
import us.bringardner.parley.net.lock.spi.LockContext;
import us.bringardner.parley.net.lock.spi.LockHandle;
import us.bringardner.parley.net.lock.spi.LockProvider;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * Locks for servers: one per JVM, for every store its servers use. Each store is registered as a
 * {@link LockDomain}; locks are taken on names within a domain (a mailbox, a maildrop, a queue
 * entry) and reach this JVM's threads and every other server that uses the store.
 * <pre>
 * Locks locks = Locks.open(LockOptions.sharing(Sharing.CLUSTER));
 * LockDomain mail = locks.domain("mail", mailRoot);
 * StoreClaim claim = mail.claimStore("imap-1");
 * try (NamedLock l = mail.lock("tony/INBOX", Mode.EXCLUSIVE, Duration.ofSeconds(5))) {
 *     ... read, change ...
 *     AtomicWrite.replace(index, l, out -&gt; write(out));
 * }
 * </pre>
 * <h2>Among threads</h2>
 * Threads wait their turn, first come first served, for as long as the request's timeout
 * ({@link LockTimeoutException} after it). A shared lock admits any number of readers, but a reader
 * that asks while a writer waits queues behind the writer, so writers aren't starved. Locks are
 * reentrant by default, as {@code synchronized} is; a request (or the options) can ask for one that
 * isn't, which throws {@link IllegalStateException} when asked again. A thread holding a name
 * shared can't ask for it exclusive (two readers upgrading would wait for each other for ever).
 * {@link #lockAll} takes names in several domains in one order (domain, then name).
 * <h2>Among servers</h2>
 * Each domain keeps its locks with a {@link LockProvider}, chosen when it is registered: the one
 * the options name, or with {@code auto} the best that fits the store's
 * {@link FileSourceCapabilities capabilities} and the {@link Sharing}: Parley's liberal
 * {@code region} locks (the store's own) where they reach every server, else its conservative
 * {@code lease} directories; a provider found with ServiceLoader whose priority is above zero
 * comes first. Two rules keep a choice from going wrong:
 * <ul>
 * <li>A provider that is UNSAFE for the store (its locks wouldn't reach every server) is refused,
 * unless the options allow it ({@link LockOptions#withAllowUnsafe}); one that can't work there is
 * always refused.</li>
 * <li>Every server must keep a store's locks the same way: the provider is recorded in the
 * store's {@value #DIRECTORY}, and a server that would use another is refused. To change it, stop
 * every server, delete the {@code provider-*} entry there, and start them with the new one.</li>
 * </ul>
 * With a coordination store ({@link LockOptions#withCoordinationStore}), every domain keeps its
 * locks there instead, chosen for that store.
 * @since 1.1.0
 */
public final class Locks implements AutoCloseable {

	/** The directory, in a store (or the coordination store), that holds its locks. */
	public static final String DIRECTORY = ".parley-net-locks";
	static final String RESERVED = ".parley/";
	static final String STORE = RESERVED + "store";
	static final String SERVER = RESERVED + "server/";

	private final LockOptions options;
	private final String ownerId;
	private final Map<String, LockDomain> domains = new LinkedHashMap<>();
	private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
	private volatile boolean closed;

	private Locks(LockOptions options, String ownerId) {
		this.options = options;
		this.ownerId = ownerId;
	}

	/**
	 * @param defaults the options every domain uses unless it is registered with its own
	 * @return the lock service
	 */
	public static Locks open(LockOptions defaults) {
		Objects.requireNonNull(defaults, "defaults");
		return new Locks(defaults, defaults.ownerId() != null ? defaults.ownerId() : defaultOwnerId());
	}

	private static String defaultOwnerId() {
		String host;
		try {
			host = InetAddress.getLocalHost().getHostName();
		} catch (IOException | RuntimeException e) {
			host = "unknown-host";
		}
		return host + "/" + ManagementFactory.getRuntimeMXBean().getName() + "/" + UUID.randomUUID().toString().substring(0, 8);
	}

	/** @return the options domains use unless registered with their own */
	public LockOptions options() {
		return options;
	}

	/** @return this JVM, as other servers see it */
	public String ownerId() {
		return ownerId;
	}

	// ------------------------------------------------------------------ domains

	/**
	 * Register a store with the default options.
	 * @param name the domain's name: letters, digits, {@code . _ -}; the same on every server, as
	 *        lock names are kept under it in a coordination store
	 * @param root the store's root directory, the same files on every server (its path may differ)
	 * @return the domain
	 * @throws LockSetupException if no provider can keep locks for it, or it would differ from the
	 *         one other servers use
	 * @throws IOException if the store can't be prepared
	 */
	public LockDomain domain(String name, FileSource root) throws IOException {
		return domain(name, root, options);
	}

	/**
	 * Register a store with options of its own (a sharing or provider for this store only).
	 * Registering the same name again returns the same domain, if it is the same root.
	 * @param name the domain's name
	 * @param root the store's root directory
	 * @param o its options (the coordination store and owner id are the service's)
	 * @return the domain
	 * @throws LockSetupException if no provider can keep locks for it, or it would differ from the
	 *         one other servers use
	 * @throws IOException if the store can't be prepared
	 */
	public synchronized LockDomain domain(String name, FileSource root, LockOptions o) throws IOException {
		checkOpen();
		Objects.requireNonNull(name, "name");
		Objects.requireNonNull(root, "root");
		Objects.requireNonNull(o, "options");
		if( !name.matches("[A-Za-z0-9._-]+") ) {
			throw new IllegalArgumentException("A domain's name is letters, digits, '.', '_' and '-': " + name);
		}
		LockDomain had = domains.get(name);
		if( had != null ) {
			if( !had.root().getAbsolutePath().equals(root.getAbsolutePath()) ) {
				throw new IllegalArgumentException("The domain " + name + " is already " + had.root().getAbsolutePath());
			}
			return had;
		}
		if( !root.isDirectory() ) {
			throw new java.io.FileNotFoundException("The store's root " + root.getAbsolutePath() + " isn't a directory");
		}
		FileSource coordination = options.coordinationStore();
		FileSource lockStore = coordination != null ? coordination : root;
		FileSource dir = lockStore.getChild(DIRECTORY);
		if( !dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory() ) {
			throw new IOException("Can't create the lock directory " + dir.getAbsolutePath());
		}
		FileSourceCapabilities caps = lockStore.getCapabilities();
		LockProvider provider = choose(o, caps, lockStore);
		ProviderMarker.check(dir, coordination != null ? name : null, provider.id());
		LockContext ctx = new LockContext(name, dir, caps, o.sharing(), ownerId, o.lease(), o.renew());
		LockService service = provider.open(ctx);
		LockService names = o.sharing() == Sharing.OFF ? new InJvmLockService() : service;
		LockDomain d = new LockDomain(this, name, root, o, provider, caps, names, service, coordination != null ? name + "/" : "");
		domains.put(name, d);
		return d;
	}

	/** @return the domain registered with this name, or null */
	public synchronized LockDomain domain(String name) {
		return domains.get(name);
	}

	/** @return the registered domains, in registration order */
	public synchronized List<LockDomain> domains() {
		return new ArrayList<>(domains.values());
	}

	private static LockProvider choose(LockOptions o, FileSourceCapabilities caps, FileSource store) throws LockSetupException {
		String want = o.provider();
		Sharing sharing = o.sharing();
		if( LockOptions.AUTO.equalsIgnoreCase(want) ) {
			LockProvider best = null;
			for (LockProvider p : ServiceLoader.load(LockProvider.class)) {
				if( p.priority() > 0 && p.fit(caps, sharing) == LockProvider.Fit.SAFE && (best == null || p.priority() > best.priority()) ) {
					best = p;
				}
			}
			if( best != null ) {
				return best;
			}
			LockProvider region = new RegionLockProvider();
			if( region.fit(caps, sharing) == LockProvider.Fit.SAFE ) {
				return region;
			}
			LockProvider lease = new LeaseLockProvider();
			if( lease.fit(caps, sharing) == LockProvider.Fit.SAFE ) {
				return lease;
			}
			throw new LockSetupException("No way to keep locks for " + store.getAbsolutePath() + " with sharing " + sharing + ": "
					+ region.whyNot(caps, sharing) + "; " + lease.whyNot(caps, sharing));
		}
		LockProvider p = find(want);
		LockProvider.Fit fit = p.fit(caps, sharing);
		if( fit == LockProvider.Fit.UNSUPPORTED || (fit == LockProvider.Fit.UNSAFE && !o.allowUnsafe()) ) {
			throw new LockSetupException("The lock provider " + p.id() + " can't be used for " + store.getAbsolutePath()
					+ " with sharing " + sharing + ": " + p.whyNot(caps, sharing)
					+ (fit == LockProvider.Fit.UNSAFE ? " (set " + LockOptions.ALLOW_UNSAFE_PROPERTY + "=true if you know better)" : ""));
		}
		return p;
	}

	/** A provider by id (Parley's, or one found with ServiceLoader) or by class name. */
	static LockProvider find(String want) throws LockSetupException {
		if( RegionLockProvider.ID.equalsIgnoreCase(want) ) {
			return new RegionLockProvider();
		}
		if( LeaseLockProvider.ID.equalsIgnoreCase(want) ) {
			return new LeaseLockProvider();
		}
		for (LockProvider p : ServiceLoader.load(LockProvider.class)) {
			if( p.id().equalsIgnoreCase(want) ) {
				return p;
			}
		}
		try {
			Class<?> c = Class.forName(want, true, Thread.currentThread().getContextClassLoader() != null
					? Thread.currentThread().getContextClassLoader() : Locks.class.getClassLoader());
			if( !LockProvider.class.isAssignableFrom(c) ) {
				throw new LockSetupException(want + " isn't a " + LockProvider.class.getName());
			}
			return (LockProvider) c.getDeclaredConstructor().newInstance();
		} catch (ClassNotFoundException e) {
			throw new LockSetupException("No lock provider " + want + " (not region, lease, an id found with ServiceLoader, or a class)");
		} catch (ReflectiveOperationException | RuntimeException e) {
			throw new LockSetupException("Can't make the lock provider " + want + ": " + e);
		}
	}

	// ------------------------------------------------------------------ several domains

	/**
	 * Take names in one or more domains, in one order (domain, then name), so two callers locking
	 * overlapping sets can't each wait for the other. If one can't be had in time, those already
	 * taken are let go. Several domains can't be changed atomically together: work spanning stores
	 * must survive a crash between them on its own.
	 * @param names what to lock
	 * @param mode shared or exclusive, for all of them
	 * @param timeout how long to wait for all of them together
	 * @return the holdings; closing the group closes them all
	 * @throws LockTimeoutException if one stayed busy past the timeout
	 * @throws IOException if a store can't be asked
	 */
	public LockGroup lockAll(Collection<LockName> names, Mode mode, Duration timeout) throws IOException {
		long deadline = System.nanoTime() + timeout.toNanos();
		List<NamedLock> got = new ArrayList<>();
		try {
			for (LockName n : new TreeSet<>(names)) {
				long left = Math.max(0, deadline - System.nanoTime());
				got.add(n.domain().request(n.name()).mode(mode).timeout(Duration.ofNanos(left)).acquire());
			}
		} catch (IOException | RuntimeException e) {
			for (int i = got.size() - 1; i >= 0; i--) {
				got.get(i).close();
			}
			throw e;
		}
		return new LockGroup(got);
	}

	// ------------------------------------------------------------------ taking and letting go

	/**
	 * Take a name. timeoutNanos < 0: don't wait at all.
	 * @param key the domain and name, unique in this JVM
	 * @param serviceName the name as the service sees it
	 */
	NamedLock acquire(LockDomain domain, String name, String key, String serviceName, LockService service, Mode mode,
			long timeoutNanos, boolean reentrant) throws IOException {
		checkOpen();
		Objects.requireNonNull(mode, "mode");
		Thread me = Thread.currentThread();
		boolean once = timeoutNanos < 0;
		long deadline = once ? 0 : System.nanoTime() + timeoutNanos;
		while (true) {
			Entry e = entries.computeIfAbsent(key, k -> new Entry(k, name, serviceName, service));
			synchronized (e) {
				if( e.dead ) {
					continue; // let go and removed between computeIfAbsent and here
				}
				NamedLock again = e.reenter(this, domain, me, mode, reentrant);
				if( again != null ) {
					return again;
				}
				Waiter w = new Waiter(me, mode);
				e.queue.addLast(w);
				boolean granted = false;
				try {
					long sleep = 1;
					while (true) {
						checkOpen();
						if( e.queue.peekFirst() == w ) {
							NamedLock l = e.grant(this, domain, w);
							if( l != null ) {
								granted = true;
								return l;
							}
							if( once ) {
								return null;
							}
						} else if( once ) {
							return null; // others are ahead of it in this JVM
						}
						long left = deadline - System.nanoTime();
						if( left <= 0 ) {
							throw new LockTimeoutException("The lock on " + domain.name() + ":" + name + " stayed busy for "
									+ Duration.ofNanos(timeoutNanos) + " (" + e.describeHolders() + ")");
						}
						long cap = e.service.pollCapMillis();
						long ms = e.queue.peekFirst() == w && e.free() ? Math.min(sleep, cap) : cap;
						sleep = Math.min(sleep * 2, cap);
						try {
							e.wait(Math.max(1, Math.min(ms, left / 1_000_000 + 1)));
						} catch (InterruptedException ie) {
							Thread.currentThread().interrupt();
							throw new InterruptedIOException("Interrupted while waiting for the lock on " + domain.name() + ":" + name);
						}
					}
				} finally {
					if( !granted ) {
						e.queue.remove(w);
						if( w.mode == Mode.EXCLUSIVE && e.free()
								&& (e.queue.isEmpty() || e.queue.peekFirst().mode != Mode.EXCLUSIVE) ) {
							e.service.cancel(e.serviceName); // no writer of this JVM waits for it any more
						}
						e.notifyAll(); // the next waiter may be at the head now
						removeIfIdle(e);
					}
				}
			}
		}
	}

	/** Called with e's monitor held. */
	void release(Entry e, NamedLock l) {
		if( e.let(l) ) {
			LockHandle h = e.handle;
			e.handle = null;
			e.handleMode = null;
			e.service.release(h);
		}
		e.notifyAll();
		removeIfIdle(e);
	}

	/** Called with e's monitor held. */
	private void removeIfIdle(Entry e) {
		if( e.free() && e.queue.isEmpty() ) {
			e.dead = true;
			entries.remove(e.key, e);
		}
	}

	void checkOpen() throws IOException {
		if( closed ) {
			throw new IOException("The lock service is closed");
		}
	}

	/**
	 * Close: what this JVM still holds is let go, claims are given up, leases stop being renewed.
	 * Threads waiting for a lock get an IOException.
	 */
	@Override
	public void close() {
		List<LockDomain> ds;
		synchronized (this) {
			closed = true;
			ds = new ArrayList<>(domains.values());
		}
		for (Entry e : entries.values()) {
			synchronized (e) {
				if( e.handle != null ) {
					e.service.release(e.handle);
					e.handle = null;
				}
				e.notifyAll();
			}
		}
		for (LockDomain d : ds) {
			d.closeServices();
		}
	}

	// ------------------------------------------------------------------ one name

	/** A thread waiting for a name, in arrival order. */
	static final class Waiter {
		final Thread thread;
		final Mode mode;

		Waiter(Thread thread, Mode mode) {
			this.thread = thread;
			this.mode = mode;
		}
	}

	/** One name, held or waited for in this JVM. Guarded by its own monitor. */
	static final class Entry {
		final String key;
		final String name;
		final String serviceName;
		final LockService service;
		final ArrayDeque<Waiter> queue = new ArrayDeque<>();
		Thread owner;
		int ownerHolds;
		final Map<Thread, Integer> readers = new HashMap<>();
		LockHandle handle;
		Mode handleMode;
		boolean dead;

		Entry(String key, String name, String serviceName, LockService service) {
			this.key = key;
			this.name = name;
			this.serviceName = serviceName;
			this.service = service;
		}

		boolean free() {
			return owner == null && readers.isEmpty();
		}

		NamedLock reenter(Locks locks, LockDomain domain, Thread t, Mode mode, boolean reentrant) {
			if( owner == t ) {
				if( !reentrant ) {
					throw new IllegalStateException("This thread already holds the lock on " + name + " (the request isn't reentrant)");
				}
				ownerHolds++;
				return new NamedLock(locks, domain, this, t, Mode.EXCLUSIVE);
			}
			Integer n = readers.get(t);
			if( n != null ) {
				if( mode == Mode.EXCLUSIVE ) {
					throw new IllegalStateException("This thread holds the lock on " + name
							+ " shared and can't upgrade it to exclusive; let it go first");
				}
				if( !reentrant ) {
					throw new IllegalStateException("This thread already holds the lock on " + name + " (the request isn't reentrant)");
				}
				readers.put(t, n + 1);
				return new NamedLock(locks, domain, this, t, Mode.SHARED);
			}
			return null;
		}

		NamedLock grant(Locks locks, LockDomain domain, Waiter w) throws IOException {
			if( free() ) {
				LockHandle h = service.tryAcquire(serviceName, w.mode);
				if( h == null ) {
					return null;
				}
				handle = h;
				handleMode = w.mode;
			} else if( !(w.mode == Mode.SHARED && owner == null && handleMode == Mode.SHARED) ) {
				return null;
			}
			queue.removeFirst();
			if( w.mode == Mode.EXCLUSIVE ) {
				owner = w.thread;
				ownerHolds = 1;
			} else {
				readers.put(w.thread, 1);
			}
			notifyAll(); // readers behind it may join
			return new NamedLock(locks, domain, this, w.thread, w.mode);
		}

		boolean let(NamedLock l) {
			if( owner == l.thread ) {
				if( --ownerHolds == 0 ) {
					owner = null;
				}
			} else {
				int n = readers.get(l.thread) - 1;
				if( n == 0 ) {
					readers.remove(l.thread);
				} else {
					readers.put(l.thread, n);
				}
			}
			return free() && handle != null;
		}

		String describeHolders() {
			if( owner != null ) {
				return "held here by " + owner.getName();
			}
			if( !readers.isEmpty() ) {
				return "held shared here by " + readers.size() + " thread(s)";
			}
			return queue.size() > 1 ? (queue.size() - 1) + " thread(s) here ahead of it" : "held by another server";
		}
	}
}
