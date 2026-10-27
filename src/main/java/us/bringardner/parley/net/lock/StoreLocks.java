package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import us.bringardner.parley.files.FileSource;

/**
 * The lock domains of file servers (FTP, SFTP, ...) in this JVM: one per store root, shared by
 * every server here that uses it, so an FTP upload and an SFTP write of one file, by servers in
 * one JVM, keep out of each other.
 * <p>
 * A root inside one already registered uses that one's domain, so servers in this JVM on nested
 * roots (FTP on {@code /srv}, SFTP on {@code /srv/tony}) lock a file under one name: its path from
 * the domain's root ({@link #fileLockName}). Servers on other machines (or in other JVMs) reach
 * the same locks when they serve the same root: the locks are kept in it (in
 * {@value Locks#DIRECTORY}, see {@link Locks}), named from it. So give every server that shares a
 * store, wherever it runs, the same root.
 * <p>
 * The lock directory is inside the root. Servers must not let clients reach it
 * ({@link #isLockFile}): a client that could delete it would break the locks.
 * <p>
 * How many servers share a root is the domain's {@link Sharing}, given when it is first
 * registered (the servers read it from a property of their own, such as
 * {@code parley.ftp.sharedStore}); a later server asking for another one is told in the log and
 * uses the domain as it is.
 */
public final class StoreLocks {

	private static final Logger LOG = Logger.getLogger(StoreLocks.class.getName());
	private static final StoreLocks INSTANCE = new StoreLocks();

	private Locks locks;
	private final Map<String, LockDomain> domains = new HashMap<>();
	private final Map<LockDomain, Integer> users = new HashMap<>();

	private StoreLocks() {
	}

	/** @return this JVM's file-server lock domains */
	public static StoreLocks get() {
		return INSTANCE;
	}

	/** @return the lock service the domains are in, opened the first time it is asked for */
	public synchronized Locks locks() {
		if( locks == null ) {
			locks = Locks.open(LockOptions.sharing(Sharing.OFF));
		}
		return locks;
	}

	/**
	 * The lock domain of a root, for a server (or session) that starts using it; match it with
	 * {@link #release(LockDomain)}. Registered the first time, with the sharing given.
	 * @param root the root
	 * @param sharing how many servers share it
	 * @return its domain
	 * @throws IOException if its locks can't be set up (see {@link Locks#domain})
	 */
	public synchronized LockDomain acquire(FileSource root, Sharing sharing) throws IOException {
		String key = key(root);
		LockDomain d = domains.get(key);
		if( d == null ) {
			d = deepest(key); // a root inside a registered one shares its domain
		}
		if( d == null ) {
			String name = "files-" + Integer.toHexString(key.hashCode());
			for (int i = 2; locks().domain(name) != null; i++) {
				name = "files-" + Integer.toHexString(key.hashCode()) + "-" + i;
			}
			d = locks().domain(name, root, locks().options().withSharing(sharing));
			domains.put(key, d);
		} else if( d.sharing() != sharing ) {
			LOG.warning("The store " + key + " is already in use here as " + d.sharing() + "; it stays so (" + sharing + " was asked)");
		}
		users.merge(d, 1, Integer::sum);
		return d;
	}

	/** A server (or session) stopped using a domain: the last one closes it. */
	public synchronized void release(LockDomain d) {
		if( d == null ) {
			return;
		}
		Integer n = users.get(d);
		if( n == null ) {
			return;
		}
		if( n > 1 ) {
			users.put(d, n - 1);
			return;
		}
		users.remove(d);
		domains.values().remove(d);
		d.close();
	}

	/**
	 * @return the domain of the deepest registered root that holds the file (or is it), or null if
	 *         none does
	 */
	public synchronized LockDomain domainOf(FileSource f) throws IOException {
		return deepest(key(f));
	}

	/**
	 * As {@link #domainOf} for a file about to be locked: the domain is kept open (a reference, as
	 * {@link #acquire} takes) until {@link #release(LockDomain)}, even if every server that
	 * registered it stops meanwhile.
	 * @return the domain, or null if no registered root holds the file
	 */
	public synchronized LockDomain acquireFor(FileSource f) throws IOException {
		LockDomain d = deepest(key(f));
		if( d == null ) {
			d = deepestAbsolute(absoluteKey(f)); // a link in a root that leads outside it
		}
		if( d != null ) {
			users.merge(d, 1, Integer::sum);
		}
		return d;
	}

	/**
	 * True if the file is (or is in) a registered root's lock directory, which clients must not
	 * see or change.
	 */
	public synchronized boolean isLockFile(FileSource f) throws IOException {
		String key = key(f);
		for (String root : domains.keySet()) {
			if( within(key, (root.endsWith("/") ? root : root + "/") + Locks.DIRECTORY) ) {
				return true;
			}
		}
		return false;
	}

	/** As deepest, by the paths as given (links not resolved). */
	private LockDomain deepestAbsolute(String key) throws IOException {
		LockDomain best = null;
		int bestLen = -1;
		for (LockDomain d : domains.values()) {
			String root = absoluteKey(d.root());
			if( within(key, root) && root.length() > bestLen ) {
				best = d;
				bestLen = root.length();
			}
		}
		return best;
	}

	private LockDomain deepest(String key) {
		LockDomain best = null;
		int bestLen = -1;
		for (Map.Entry<String, LockDomain> e : domains.entrySet()) {
			String root = e.getKey();
			if( within(key, root) && root.length() > bestLen ) {
				best = e.getValue();
				bestLen = root.length();
			}
		}
		return best;
	}

	private static boolean within(String key, String root) {
		return key.equals(root) || key.startsWith(root.endsWith("/") ? root : root + "/");
	}

	/**
	 * A file's lock name in a domain: {@code file/} and its path from the domain's root, the same on
	 * every server whatever the root's path there. The path is the file's real one (links
	 * resolved); for a link in the root that leads outside it, the link's own.
	 * @throws IllegalArgumentException if the file isn't under the domain's root
	 */
	public static String fileLockName(LockDomain d, FileSource f) throws IOException {
		String root = key(d.root());
		String key = key(f);
		if( !within(key, root) ) {
			root = absoluteKey(d.root());
			key = absoluteKey(f);
			if( !within(key, root) ) {
				throw new IllegalArgumentException(key + " isn't under " + root);
			}
		}
		String rel = key.length() > root.length() ? key.substring(root.length() + (root.endsWith("/") ? 0 : 1)) : "";
		return "file/" + rel;
	}

	/** A file's path as given (links not resolved), with '/'. */
	static String absoluteKey(FileSource f) {
		String key = f.getAbsolutePath().replace('\\', '/');
		while( key.length() > 1 && key.endsWith("/") ) {
			key = key.substring(0, key.length() - 1);
		}
		return key;
	}

	/** A file's path as this class compares them: canonical (links resolved), with '/'. */
	public static String key(FileSource f) throws IOException {
		String key;
		try {
			key = f.getCanonicalPath();
		} catch (IOException e) {
			key = f.getAbsolutePath();
		}
		key = key.replace('\\', '/');
		while( key.length() > 1 && key.endsWith("/") ) {
			key = key.substring(0, key.length() - 1);
		}
		return key;
	}

	/** @return how many servers share their store, from a system property (off, host, cluster; default off) */
	public static Sharing sharing(String property) {
		return Sharing.parse(System.getProperty(property));
	}

	/**
	 * This server's id among those that share its store: the system property's value, or the
	 * host, the server's name and its port (or this process's id where there is no port).
	 */
	public static String serverId(String property, String serverName, int port) {
		return serverIdOf(property == null ? null : System.getProperty(property), serverName, port);
	}

	/**
	 * This server's id among those that share its store: the id it was given (from its own
	 * configuration), or, when none, the host, the server's name and its port (or this process's
	 * id where there is no port).
	 * @param configured the id from the server's settings, or null
	 * @since 2.0.0
	 */
	public static String serverIdOf(String configured, String serverName, int port) {
		String id = configured;
		if( id == null || id.isBlank() ) {
			String host;
			try {
				host = InetAddress.getLocalHost().getHostName();
			} catch (IOException | RuntimeException e) {
				host = "host";
			}
			String where = port > 0 ? String.valueOf(port) : "pid" + pid();
			id = host + "-" + serverName + "-" + where;
		}
		return id.replaceAll("[^A-Za-z0-9._-]", "_");
	}

	private static String pid() {
		String n = ManagementFactory.getRuntimeMXBean().getName(); // pid@host
		int at = n.indexOf('@');
		return at > 0 ? n.substring(0, at) : n;
	}
}
