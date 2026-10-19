package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.lock.spi.LockHandle;
import us.bringardner.parley.net.lock.spi.LockService;

/**
 * Locks as lease directories, for stores whose own locks don't reach every server (FTP, SFTP, a
 * local disk shared between machines). The only thing asked of the store is what every FileSource
 * does atomically: {@code mkdir} of a directory that exists fails.
 * <ul>
 * <li>Every entry is a lease directory owned by one server (this space): whoever makes it holds
 * it, writes {@code owner} in it (the name, the owner id, a token for this holding and a beat
 * count), renews it every renew interval by writing {@code owner} again with the next beat (after
 * checking the token is still its own), and deletes it on release. Nobody relies on an entry they
 * didn't make.</li>
 * <li>A writer makes the name's marker, {@code leases/<hash>.w}, and goes in once no live reader
 * entry is left. The marker stays (renewed) while it waits, so no new reader comes in: writers
 * aren't starved.</li>
 * <li>Readers: each server that reads the name has its own entry, {@code leases/<hash>.r.<id>},
 * made only while there is no marker, and taken back if a marker appeared while it was being
 * made. Any number of servers read at once; within a server, its threads share its one entry.</li>
 * <li>Staleness is judged without trusting any clock but this JVM's own: an entry whose
 * {@code owner} (or its absence, for a holder that died before writing it) stays the same for a
 * whole lease, as seen from here, belongs to a holder that stopped renewing. It is taken over:
 * re-read to check it is still the same, renamed aside to a unique name, and deleted. Two servers
 * taking over the same stale entry at once can end with the second removing the first's new one;
 * that holder finds out at its next renewal (or {@link LockHandle#verify()}).</li>
 * </ul>
 * The order "announce, then look" on both sides is correct on a store that applies each operation
 * in one order (one FTP, SFTP or file server: {@link us.bringardner.parley.files.FileSourceCapabilities#orderedOperations()}).
 * On a store that doesn't promise it, shared requests are held exclusive between servers.
 */
final class LeaseLockService implements LockService {

	private static final Logger LOG = Logger.getLogger(LeaseLockService.class.getName());
	static final String DIR = "leases";
	static final String OWNER = "owner";
	/** The writer's marker: {@code <hash>.w}. */
	static final String WRITER = ".w";
	/** A reader server's entry: {@code <hash>.r.<reader id>}. */
	static final String READER = ".r.";
	private static final String NO_OWNER = "";
	private static final String STALE = ".stale-";

	private final FileSource dir;
	private final String ownerId;
	private final long leaseNanos;
	private final long renewMillis;
	private final Set<LeaseHandle> held = ConcurrentHashMap.newKeySet();
	/** Writer markers made while this JVM waits for readers to finish, by name. */
	private final Map<String, LeaseHandle> pending = new ConcurrentHashMap<>();
	/** This space's name in reader entries: one entry per server, whatever its id. */
	private final String readerId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
	/** What each busy name looked like when first seen so, and when (nanoTime). */
	private final Map<String, Observation> seen = new ConcurrentHashMap<>();
	private final ScheduledExecutorService renewer;

	/** Whether readers on several servers may share a name (the store applies operations in one order). */
	private final boolean shareAcrossServers;

	LeaseLockService(FileSource lockDir, String ownerId, Duration lease, Duration renew, boolean shareAcrossServers) throws IOException {
		this.shareAcrossServers = shareAcrossServers;
		dir = lockDir.getChild(DIR);
		if( !dir.isDirectory() && !dir.mkdirs() && !dir.isDirectory() ) {
			throw new IOException("Can't create the lease directory " + dir.getAbsolutePath());
		}
		this.ownerId = ownerId;
		this.leaseNanos = lease.toNanos();
		this.renewMillis = renew.toMillis();
		renewer = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "parley-lease-renewer");
			t.setDaemon(true);
			return t;
		});
		renewer.scheduleWithFixedDelay(this::renewAll, renewMillis, renewMillis, TimeUnit.MILLISECONDS);
	}

	static String dirName(String name) {
		try {
			byte[] h = MessageDigest.getInstance("SHA-256").digest(name.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(32);
			for (int i = 0; i < 16; i++) {
				sb.append(Character.forDigit((h[i] >> 4) & 0xF, 16)).append(Character.forDigit(h[i] & 0xF, 16));
			}
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is required of every JVM", e);
		}
	}

	@Override
	public LockHandle tryAcquire(String name, Mode mode) throws IOException {
		String base = dirName(name);
		// without one order of operations, a reader's "announce, then look" can't be trusted: shared
		// requests are then held exclusive between servers (stricter, never weaker)
		return mode == Mode.SHARED && shareAcrossServers ? tryRead(name, base) : tryWrite(name, base);
	}

	/**
	 * Exclusive: make the writer marker (kept, and renewed, while this JVM waits, so no new readers
	 * come in), then go in once no live reader is left.
	 */
	private LockHandle tryWrite(String name, String base) throws IOException {
		LeaseHandle w = pending.get(name);
		if( w == null ) {
			FileSource wd = dir.getChild(base + WRITER);
			w = make(name, wd);
			if( w == null ) {
				if( !clearIfStale(wd) ) {
					return null; // another writer
				}
				w = make(name, wd);
				if( w == null ) {
					return null;
				}
			}
			pending.put(name, w);
		}
		if( liveReaders(base) ) {
			return null; // they finish first; the marker keeps others from joining them
		}
		pending.remove(name);
		return w;
	}

	/**
	 * Shared: no writer may be in or waiting. Make this server's reader entry, then look again: a
	 * writer that came in meanwhile goes first, so the entry is taken back. (A writer makes its
	 * marker before it looks for readers, and a reader its entry before it looks again for a writer,
	 * so one of them always sees the other.)
	 */
	private LockHandle tryRead(String name, String base) throws IOException {
		FileSource wd = dir.getChild(base + WRITER);
		if( wd.exists() && (!clearIfStale(wd) || wd.exists()) ) {
			return null;
		}
		FileSource rd = dir.getChild(base + READER + readerId);
		LeaseHandle r = make(name, rd);
		if( r == null ) {
			if( !clearIfStale(rd) ) {
				return null;
			}
			r = make(name, rd);
			if( r == null ) {
				return null;
			}
		}
		if( wd.exists() ) {
			release(r);
			return null;
		}
		return r;
	}

	@Override
	public void cancel(String name) {
		LeaseHandle w = pending.remove(name);
		if( w != null ) {
			release(w);
		}
	}

	/** Whether a live reader holds the name; dead readers' entries are taken over on the way. */
	private boolean liveReaders(String base) throws IOException {
		FileSource[] kids = dir.listFiles();
		boolean live = false;
		if( kids != null ) {
			for (FileSource k : kids) {
				String n = k.getName();
				if( n.startsWith(base + READER) && !n.contains(STALE) && !clearIfStale(k) ) {
					live = true;
				}
			}
		}
		return live;
	}

	/**
	 * A lease directory that someone else holds: is it gone, or dead (and so taken over now)?
	 * @return true if it is gone (released, or taken over by this call); false if it is held
	 */
	private boolean clearIfStale(FileSource d) throws IOException {
		String key = d.getName();
		String content = read(d);
		if( content == null ) {
			seen.remove(key);
			return true;
		}
		if( stale(key, content) ) {
			takeOver(d, content);
			return !d.exists();
		}
		return false;
	}

	/** @return the holding if this call made the directory, else null */
	private LeaseHandle make(String name, FileSource d) throws IOException {
		if( !d.mkdir() ) {
			return null;
		}
		LeaseHandle h = new LeaseHandle(name, d, UUID.randomUUID().toString());
		try {
			write(h);
		} catch (IOException | RuntimeException e) {
			deleteQuietly(d);
			throw e;
		}
		h.lastRenew = System.nanoTime();
		held.add(h);
		seen.remove(d.getName());
		return h;
	}

	/** Whether a lease directory has looked the same for a whole lease, as seen from here. */
	private boolean stale(String key, String content) {
		long now = System.nanoTime();
		Observation o = seen.get(key);
		if( o == null || !o.content.equals(content) ) {
			seen.put(key, new Observation(content, now));
			return false;
		}
		return now - o.since >= leaseNanos;
	}

	/** Remove a stale lock, if it is still the one seen. */
	private void takeOver(FileSource d, String staleContent) throws IOException {
		if( !staleContent.equals(read(d)) ) {
			return; // renewed, released or taken meanwhile
		}
		FileSource aside = dir.getChild(d.getName() + STALE + UUID.randomUUID());
		if( !d.renameTo(aside) ) {
			return; // someone else moved it first
		}
		String moved = read(aside);
		deleteTree(aside);
		if( !staleContent.equals(moved) ) {
			LOG.warning("Took over " + d.getName() + " just as it was renewed or taken again; its holder loses it at its next renewal");
		} else {
			LOG.info("Took over the stale lock " + d.getName() + " (" + firstLine(staleContent) + ")");
		}
	}

	@Override
	public void release(LockHandle handle) {
		LeaseHandle h = (LeaseHandle) handle;
		synchronized (h) {
			h.released = true;
			held.remove(h);
			try {
				if( ownedBy(read(h.dir), h.token) ) {
					h.dir.getChild(OWNER).delete();
					if( !h.dir.delete() ) {
						LOG.warning("Can't remove the lease directory " + h.dir.getAbsolutePath());
					}
				}
			} catch (IOException | RuntimeException e) {
				LOG.log(Level.WARNING, "Releasing the lease " + h.dir.getAbsolutePath(), e);
			}
		}
	}

	@Override
	public long pollCapMillis() {
		return 250;
	}

	@Override
	public void close() {
		for (String name : new java.util.ArrayList<>(pending.keySet())) {
			cancel(name);
		}
		renewer.shutdownNow();
	}

	@Override
	public String toString() {
		return "lease directories in " + dir.getAbsolutePath();
	}

	// ------------------------------------------------------------------ renewing

	private void renewAll() {
		for (LeaseHandle h : held) {
			renew(h);
		}
	}

	private void renew(LeaseHandle h) {
		synchronized (h) {
			if( h.released || h.lost ) {
				return;
			}
			try {
				if( !ownedBy(read(h.dir), h.token) ) {
					h.lost = true;
					LOG.warning("Lost the lease on " + h.name + ": another server took it over");
					return;
				}
				h.beat++;
				write(h);
				h.lastRenew = System.nanoTime();
			} catch (IOException | RuntimeException e) {
				LOG.log(Level.FINE, "Renewing the lease on " + h.name, e);
				if( System.nanoTime() - h.lastRenew >= leaseNanos ) {
					h.lost = true;
					LOG.warning("Lost the lease on " + h.name + ": it couldn't be renewed for a whole lease (" + e + ")");
				}
			}
		}
	}

	@Override
	public long claimWaitMillis() {
		return leaseNanos / 1_000_000 + renewMillis * 2;
	}

	// ------------------------------------------------------------------ the owner file

	private void write(LeaseHandle h) throws IOException {
		String content = "name=" + URLEncoder.encode(h.name, StandardCharsets.UTF_8) + "\nowner="
				+ URLEncoder.encode(ownerId, StandardCharsets.UTF_8) + "\ntoken=" + h.token + "\nbeat=" + h.beat + "\n";
		try (OutputStream out = h.dir.getChild(OWNER).getOutputStream()) {
			out.write(content.getBytes(StandardCharsets.UTF_8));
		}
	}

	/** @return the owner file's content, "" if the directory has none, null if there is no directory */
	private static String read(FileSource d) throws IOException {
		FileSource f = d.getChild(OWNER);
		try (InputStream in = f.getInputStream()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			if( f.exists() ) {
				throw e;
			}
			return d.exists() ? NO_OWNER : null;
		}
	}

	private static boolean ownedBy(String content, String token) {
		return content != null && content.contains("\ntoken=" + token + "\n");
	}

	private static String field(String content, String key) {
		for (String line : content.split("\n")) {
			if( line.startsWith(key + "=") ) {
				return URLDecoder.decode(line.substring(key.length() + 1), StandardCharsets.UTF_8);
			}
		}
		return null;
	}

	private static String firstLine(String content) {
		if( content.isEmpty() ) {
			return "no owner written";
		}
		String owner = field(content, "owner");
		return "owner " + owner;
	}

	private static void deleteTree(FileSource d) {
		try {
			FileSource[] kids = d.listFiles();
			if( kids != null ) {
				for (FileSource k : kids) {
					k.delete();
				}
			}
			d.delete();
		} catch (IOException | RuntimeException e) {
			LOG.log(Level.WARNING, "Removing " + d.getAbsolutePath(), e);
		}
	}

	private static void deleteQuietly(FileSource d) {
		deleteTree(d);
	}

	private static final class Observation {
		final String content;
		final long since;

		Observation(String content, long since) {
			this.content = content;
			this.since = since;
		}
	}

	final class LeaseHandle implements LockHandle {
		final String name;
		final FileSource dir;
		final String token;
		long beat;
		volatile long lastRenew;
		volatile boolean lost;
		volatile boolean released;

		LeaseHandle(String name, FileSource dir, String token) {
			this.name = Objects.requireNonNull(name);
			this.dir = dir;
			this.token = token;
		}

		@Override
		public boolean isValid() {
			return !released && !lost && System.nanoTime() - lastRenew < leaseNanos;
		}

		@Override
		public void verify() throws IOException {
			if( released ) {
				throw new LockLostException("The lock on " + name + " was released");
			}
			if( lost || System.nanoTime() - lastRenew >= leaseNanos ) {
				lost = true;
				throw new LockLostException("The lease on " + name + " ran out");
			}
			if( !ownedBy(read(dir), token) ) {
				lost = true;
				throw new LockLostException("The lease on " + name + " was taken over by another server");
			}
		}
	}
}
