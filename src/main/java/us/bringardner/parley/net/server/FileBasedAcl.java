package us.bringardner.parley.net.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.sasl.ScramMechanism;
import us.bringardner.parley.net.server.IPrincipal.State;
import us.bringardner.parley.io.IoUtils;


/**
 * Users are defined one per line:
 * <pre>
 * name , password , perm1|perm2 , key=val|key=val
 * </pre>
 * The password may be plain text (not recommended) or a hash created with
 * {@link #hashPassword(char[])}, e.g. 
 * <pre>
 * java -cp ... us.bringardner.parley.net.server.FileBasedAcl mySecret
 * </pre>
 * which prints a value like {PBKDF2}210000:salt:hash to paste into the password field.
 * <p>
 * For SCRAM logins (SCRAM-SHA-1, SCRAM-SHA-256) a hashed password can carry SCRAM credentials 
 * after it, each after a {@code ;}:
 * <pre>
 * {PBKDF2}210000:salt:hash;{SCRAM-SHA-256}4096:salt:storedKey:serverKey;{SCRAM-SHA-1}4096:...
 * </pre>
 * {@code FileBasedAcl --scram mySecret} prints such a value ({@link #hashPasswordWithScram(char[])}).
 * A plain text password serves SCRAM too (its credentials are made when first asked for).
 * When a password changes, replace the whole field: SCRAM credentials left from the old password
 * would still let the old password in with SCRAM.
 * SCRAM is offered ({@link #supportsScram(String)}) only when every user in the file can use it,
 * since a client that picks SCRAM can't fall back to a password for a user who can't.
 * <p>
 * A user file on the file system is read again when it changes (checked at most every
 * {@value #PROP_RELOAD_SECONDS} seconds, default 15), so users can be added, removed or given new
 * passwords while the server runs. If the new file can't be read, the users read before stay.
 *
 * <PRE>
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 */
public class FileBasedAcl extends BaseObject implements IAccessControlList {

	public static String PROP_FILE_NAME = "userFile";

	public static final String HASH_PREFIX = "{PBKDF2}";
	/** Starts SCRAM-SHA-256 credentials after a hashed password, see the class comment. @since 1.1.0 */
	public static final String SCRAM_SHA_256_PREFIX = "{SCRAM-SHA-256}";
	/** Starts SCRAM-SHA-1 credentials after a hashed password, see the class comment. @since 1.1.0 */
	public static final String SCRAM_SHA_1_PREFIX = "{SCRAM-SHA-1}";
	private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
	private static final int HASH_ITERATIONS = 210000;
	private static final int HASH_BITS = 256;
	private static final int SALT_BYTES = 16;

	/*
	 * Each PBKDF2 hash takes a few hundred ms of CPU by design. Unlimited, a burst of login
	 * attempts (wrong passwords or made-up user names cost the same) uses every core and slows
	 * every transfer and session. So only a few run at once; the rest wait their turn.
	 */
	/** System property: how many password hashes may run at once (default: half the cores, at least 1) */
	public static final String PROP_MAX_CONCURRENT_HASHES = "parley.net.acl.maxConcurrentHashes";
	/** System property: ms a login waits for its turn before it fails (default 30000) */
	public static final String PROP_HASH_WAIT_MS = "parley.net.acl.hashWaitMs";
	public static final int DEFAULT_HASH_WAIT_MS = 30000;

	private static volatile int maxConcurrentHashes = Math.max(1, Integer.getInteger(PROP_MAX_CONCURRENT_HASHES,
			Runtime.getRuntime().availableProcessors() / 2));
	private static volatile Semaphore hashPermits = new Semaphore(maxConcurrentHashes, true);
	private static volatile long hashWaitMs = Math.max(0, Long.getLong(PROP_HASH_WAIT_MS, DEFAULT_HASH_WAIT_MS));
	private static final AtomicInteger hashesInProgress = new AtomicInteger();

	/** @return how many password hashes may run at once */
	public static int getMaxConcurrentHashes() {
		return maxConcurrentHashes;
	}

	/**
	 * @param max how many password hashes may run at once (at least 1). Hashes already running
	 * or waiting finish under the old limit.
	 */
	public static synchronized void setMaxConcurrentHashes(int max) {
		if( max < 1 ) {
			throw new IllegalArgumentException("max must be at least 1");
		}
		maxConcurrentHashes = max;
		hashPermits = new Semaphore(max, true);
	}

	/** @return ms a password check waits for its turn before it fails */
	public static long getHashWaitMs() {
		return hashWaitMs;
	}

	/** @param ms ms a password check waits for its turn before it fails (the login fails) */
	public static void setHashWaitMs(long ms) {
		if( ms < 0 ) {
			throw new IllegalArgumentException("ms must be >= 0");
		}
		hashWaitMs = ms;
	}

	/** @return password hashes running right now (for monitoring and tests) */
	public static int getHashesInProgress() {
		return hashesInProgress.get();
	}

	/**
	 * @return a salted PBKDF2 hash of the password, suitable for the password field of the user file.
	 */
	public static String hashPassword(char[] password) {
		byte[] salt = new byte[SALT_BYTES];
		new SecureRandom().nextBytes(salt);
		Semaphore permits = hashPermits;
		permits.acquireUninterruptibly();
		byte[] hash;
		try {
			hash = pbkdf2(password, salt, HASH_ITERATIONS, HASH_BITS);
		} finally {
			permits.release();
		}
		Base64.Encoder enc = Base64.getEncoder();
		return HASH_PREFIX+HASH_ITERATIONS+":"+enc.encodeToString(salt)+":"+enc.encodeToString(hash);
	}

	/**
	 * @return {@link #hashPassword(char[])} followed by SCRAM-SHA-256 and SCRAM-SHA-1 credentials,
	 * for the password field of a user who may log in with SCRAM
	 * @since 1.1.0
	 */
	public static String hashPasswordWithScram(char[] password) {
		String pw = new String(password);
		return hashPassword(password)
				+";"+SCRAM_SHA_256_PREFIX+ScramMechanism.SHA_256.newCredentials(pw).format()
				+";"+SCRAM_SHA_1_PREFIX+ScramMechanism.SHA_1.newCredentials(pw).format();
	}

	/**
	 * @return true if the password matches a value created by {@link #hashPassword(char[])}.
	 */
	public static boolean verifyPassword(char[] password, String stored) {
		if( password == null || stored == null || !stored.startsWith(HASH_PREFIX)) {
			return false;
		}
		String parts[] = stored.substring(HASH_PREFIX.length()).split(":");
		if( parts.length != 3 ) {
			return false;
		}
		try {
			int iterations = Integer.parseInt(parts[0]);
			byte[] salt = Base64.getDecoder().decode(parts[1]);
			byte[] expected = Base64.getDecoder().decode(parts[2]);
			// Wait for a turn; a login that can't get one in time fails (the client can retry)
			Semaphore permits = hashPermits;
			if( !permits.tryAcquire(hashWaitMs, TimeUnit.MILLISECONDS) ) {
				return false;
			}
			byte[] actual;
			try {
				actual = pbkdf2(password, salt, iterations, expected.length*8);
			} finally {
				permits.release();
			}
			return MessageDigest.isEqual(expected, actual);
		} catch (IllegalArgumentException e) {
			return false;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	/** Caller holds a permit from hashPermits. */
	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bits) {
		hashesInProgress.incrementAndGet();
		try {
			KeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
			return SecretKeyFactory.getInstance(HASH_ALGORITHM).generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(HASH_ALGORITHM+" not available", e);
		} finally {
			hashesInProgress.decrementAndGet();
		}
	}

	/**
	 * Print the hash of each argument, for use in a user file.
	 */
	public static void main(String[] args) {
		boolean scram = args.length > 0 && args[0].equals("--scram");
		if( args.length == (scram ? 1 : 0) ) {
			System.err.println("Usage: FileBasedAcl [--scram] password [password ...]");
			return;
		}
		for (int idx = scram ? 1 : 0; idx < args.length; idx++) {
			char[] pw = args[idx].toCharArray();
			System.out.println(scram ? hashPasswordWithScram(pw) : hashPassword(pw));
		}
	}

	public static class FileBasedPrincipal extends AbstractPrincipal {

		private final Map<String, ScramCredentials> scram = new HashMap<>();

		public FileBasedPrincipal(String name) {
			super(name);			
		}

		/**
		 * @param hash "SHA-1" or "SHA-256"
		 * @return the SCRAM credentials for that hash: those from the user file, or made from a 
		 * plain text password (once); null if there are none
		 * @since 1.1.0
		 */
		public synchronized ScramCredentials getScramCredentials(String hash) {
			ScramCredentials ret = scram.get(hash);
			if( ret == null ) {
				byte mine [] = getCredentials();
				ScramMechanism m = mechanism(hash);
				if( mine != null && m != null ) {
					String stored = new String(mine, StandardCharsets.UTF_8);
					if( !stored.startsWith(HASH_PREFIX)) {
						// a salt that is the same at every load, so it doesn't tell a real user from
						// an unknown one (whose made up salt never changes)
						ret = m.deriveCredentials(stored, stableSalt(getName(), m.getHash()), ScramMechanism.DEFAULT_ITERATIONS);
						scram.put(hash, ret);
					}
				}
			}
			return ret;
		}

		/** @since 1.1.0 */
		public synchronized void setScramCredentials(String hash, ScramCredentials credentials) {
			if( credentials == null ) {
				scram.remove(hash);
			} else {
				scram.put(hash, credentials);
			}
		}

		/** True if a SCRAM login with this hash can work: credentials kept, or a plain text password. */
		synchronized boolean canUseScram(String hash) {
			if( scram.containsKey(hash) ) {
				return true;
			}
			byte mine [] = getCredentials();
			return mine != null && mechanism(hash) != null 
					&& !new String(mine, StandardCharsets.UTF_8).startsWith(HASH_PREFIX);
		}

		@Override
		public boolean authenticate(byte[] credentials) {
			byte mine [] = getCredentials();
			if( mine == null || credentials == null ) {
				return false;
			}
			String stored = new String(mine, StandardCharsets.UTF_8);
			if( stored.startsWith(HASH_PREFIX)) {
				return verifyPassword(new String(credentials, StandardCharsets.UTF_8).toCharArray(), stored);
			}
			// Plain text password. Constant time compare so response time doesn't leak how much matched.
			return MessageDigest.isEqual(mine, credentials);
		}
	}

	private volatile Map<String , IPrincipal> users = new HashMap<>();
	/** The map parseLine fills while a file is read (then it replaces users) */
	private Map<String , IPrincipal> loading;
	private volatile boolean hasHashedPasswords = false;

	/**
	 * System property: how often (seconds) the user file is checked for changes, so users added or
	 * changed while a server runs can log in without a restart; 0 never checks. Default 15.
	 * @since 2.0.0
	 */
	public static final String PROP_RELOAD_SECONDS = "parley.net.acl.reloadSeconds";
	public static final int DEFAULT_RELOAD_SECONDS = 15;
	/** The user file when it was read from the file system (not a class path resource), else null */
	private volatile File sourceFile;
	private volatile long sourceModified;
	private volatile long sourceLength;
	private volatile long lastCheck;
	private static volatile String dummyHash;

	public FileBasedAcl() {
		super();					
	}

	@Override
	public void initialize(IServer server) throws IOException {
		if (server instanceof BaseObject) {
			useConfigurationOf((BaseObject) server);
		}
		initialize(server.getPropertyPrefix());
	}

	@Override
	public void initialize(String serverName) throws IOException {
		setPropertyPrefix(serverName);

		String path = getProperty(propertyName(PROP_FILE_NAME));
		if( path == null ) {
			throw new IOException("Can't find a property for "+PROP_FILE_NAME+" ");
		}

		// first try to get file from path
		InputStream in = getClass().getResourceAsStream(path);
		if( in == null ) {
			in = getClass().getResourceAsStream("/"+path);
		}
		if( in == null ) {
			initialize(new File(path));
			return;
		}


		load(in);		
	}

	/**
	 * Read the users from this file (and again whenever it changes, see {@link #PROP_RELOAD_SECONDS}),
	 * without a property naming it.
	 *
	 * @throws IOException if the file can't be read
	 * @since 2.0.0
	 */
	public void initialize(File f) throws IOException {
		File file = f.getCanonicalFile();
		if(!file.exists() || !file.canRead()) {
			throw new IOException(f+" is not a valid file");
		}
		long modified = file.lastModified();
		long length = file.length();
		load(new FileInputStream(file));
		sourceModified = modified;
		sourceLength = length;
		lastCheck = System.currentTimeMillis();
		sourceFile = file;
	}

	/** The file the users were read from, or null (a class path resource) */
	public File getSourceFile() {
		return sourceFile;
	}

	private synchronized void load(InputStream in) throws IOException {
		Map<String, IPrincipal> map = new HashMap<>();
		loading = map;
		try {
			String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
			for(String line : text.split("[\n]")) {
				line = line.trim();
				if( !line.isEmpty()&& !line.startsWith("#")) {
					parseLine(line);					
				}
			}
			users = map;
		} finally {
			loading = null;
			IoUtils.closeQuietly(in);
		}
	}

	/**
	 * Read the user file again if it changed since it was read (checked at most every
	 * {@value #PROP_RELOAD_SECONDS} seconds). If it can't be read, the users read before stay.
	 *
	 * @return true if the users were read again
	 * @since 2.0.0
	 */
	public boolean reloadIfChanged() {
		File f = sourceFile;
		if( f == null ) {
			return false;
		}
		long now = System.currentTimeMillis();
		long interval = getIntProperty(PROP_RELOAD_SECONDS, (int) DEFAULT_RELOAD_SECONDS) * 1000L;
		if( interval <= 0 || now - lastCheck < interval ) {
			return false;
		}
		return reload(f, now);
	}

	/**
	 * Read the user file again now if it changed, whatever the interval (for an application that
	 * just changed it).
	 *
	 * @return true if the users were read again
	 * @since 2.0.0
	 */
	public boolean reloadNow() {
		File f = sourceFile;
		return f != null && reload(f, System.currentTimeMillis());
	}

	private synchronized boolean reload(File f, long now) {
		lastCheck = now;
		long modified = f.lastModified();
		long length = f.length();
		if( modified == sourceModified && length == sourceLength ) {
			return false;
		}
		try {
			try (FileInputStream in = new FileInputStream(f)) {
				load(in);
			}
			logInfo("Read the user file "+f+" again");
			return true;
		} catch (IOException | RuntimeException e) {
			logError("Can't read the user file "+f+" again; the users read before stay", e);
			return false;
		} finally {
			// don't try again until it changes again
			sourceModified = modified;
			sourceLength = length;
		}
	}

	protected void parseLine(String line) {

		String parts[] = line.split("[,]");
		// need at least name and credentials
		if( parts.length < 3) {
			return ;
		}

		// CLean up parts
		for (int idx = 0; idx < parts.length; idx++) {
			parts[idx] = parts[idx].trim();
		}

		FileBasedPrincipal p = new FileBasedPrincipal(parts[0].trim());
		//user1  , password   , one|two|three|four|five, key=val|key=val
		String password = parts[1].trim();
		if( password.startsWith(HASH_PREFIX)) {
			hasHashedPasswords = true;
			// a hashed password may carry SCRAM credentials: ;{SCRAM-SHA-256}...;{SCRAM-SHA-1}...
			String fields[] = password.split(";");
			password = fields[0].trim();
			for (int idx = 1; idx < fields.length; idx++) {
				String f = fields[idx].trim();
				if( f.startsWith(SCRAM_SHA_256_PREFIX)) {
					p.setScramCredentials(ScramMechanism.SHA_256.getHash(), parseScram(p, f.substring(SCRAM_SHA_256_PREFIX.length())));
				} else if( f.startsWith(SCRAM_SHA_1_PREFIX)) {
					p.setScramCredentials(ScramMechanism.SHA_1.getHash(), parseScram(p, f.substring(SCRAM_SHA_1_PREFIX.length())));
				} else if( !f.isEmpty()) {
					logError("Ignoring an unknown credential for "+p.getName());
				}
			}
		}
		p.setCredentials(password.getBytes(StandardCharsets.UTF_8));
		(loading != null ? loading : users).put(p.getName(),p);
		if( parts.length> 2) {
			if( !parts[2].isEmpty()) {
				String perms [] = parts[2].split("[|]");
				for(String p1 : perms) {
					p1 = p1.trim();
					if( !p1.isEmpty()) {
						p.add(new Permission(p1.trim()));
					}
				}
			}
			if( parts.length> 3) {
				if( !parts[3].isEmpty()) {
					String args [] = parts[3].split("[|]");
					for(String a1 : args) {
						String a2[] = a1.split("[=]");
						if( a2.length == 2) {
							p.setParameter(a2[0].trim(), a2[1].trim());
						}
					}	
				}
			}
		}			
	}

	private ScramCredentials parseScram(IPrincipal p, String text) {
		ScramCredentials ret = ScramCredentials.parse(text);
		if( ret == null ) {
			logError("Ignoring malformed SCRAM credentials for "+p.getName());
		}
		return ret;
	}

	/** Makes the salt of SCRAM credentials for plain text passwords the same each time (this JVM). */
	private static final byte[] SALT_SECRET = new byte[32];
	static {
		new SecureRandom().nextBytes(SALT_SECRET);
	}

	private static byte[] stableSalt(String user, String hash) {
		try {
			javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
			mac.init(new javax.crypto.spec.SecretKeySpec(SALT_SECRET, "HmacSHA256"));
			return java.util.Arrays.copyOf(mac.doFinal((user+"\0"+hash).getBytes(StandardCharsets.UTF_8)), 16);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	/** @return the mechanism for "SHA-1" or "SHA-256" (any case), or null */
	private static ScramMechanism mechanism(String hash) {
		if( hash == null ) {
			return null;
		}
		String h = hash.toUpperCase(Locale.ROOT);
		return h.equals(ScramMechanism.SHA_256.getHash()) ? ScramMechanism.SHA_256 
				: h.equals(ScramMechanism.SHA_1.getHash()) ? ScramMechanism.SHA_1 : null;
	}

	/**
	 * True when every user in the file can log in with SCRAM using this hash (SCRAM credentials,
	 * or a plain text password), and there is at least one user.
	 */
	@Override
	public boolean supportsScram(String hash) {
		reloadIfChanged();
		ScramMechanism m = mechanism(hash);
		Map<String, IPrincipal> u = users;
		if( m == null || u.isEmpty() ) {
			return false;
		}
		for (IPrincipal p : u.values()) {
			if( !(p instanceof FileBasedPrincipal) || !((FileBasedPrincipal)p).canUseScram(m.getHash())) {
				return false;
			}
		}
		return true;
	}

	@Override
	public ScramCredentials getScramCredentials(String user, String hash) {
		reloadIfChanged();
		ScramMechanism m = mechanism(hash);
		IPrincipal p = user == null || m == null ? null : users.get(user);
		return p instanceof FileBasedPrincipal ? ((FileBasedPrincipal)p).getScramCredentials(m.getHash()) : null;
	}

	@Override
	public boolean checkPermission(IPrincipal user, IPermission action) {
		boolean ret = false;
		if( user != null && action != null && user.getState() == State.Authenticated) {
			ret = user.hasPermission(action);
		}		
		return ret;
	}


	@Override
	public void authenticateUnknownUser(byte[] credentials) {
		// Plain text compares take no measurable time, only hashed passwords need matching work.
		if( hasHashedPasswords ) {
			String hash = dummyHash;
			if( hash == null ) {
				hash = dummyHash = hashPassword("not a real password".toCharArray());
			}
			char [] pw = credentials == null ? new char[0] : new String(credentials, StandardCharsets.UTF_8).toCharArray();
			verifyPassword(pw, hash);
		}
	}

	@Override
	public IPrincipal getPrincipal(String user) {
		reloadIfChanged();
		IPrincipal ret = users.get(user);

		return ret;
	}



}
