package us.bringardner.parley.net.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.BasicParleyPermission;
import us.bringardner.parley.iam.BasicParleyPrincipal;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.GroupManager;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.io.IoUtils;
import us.bringardner.parley.net.sasl.ScramCredentials;
import us.bringardner.parley.net.sasl.ScramMechanism;


/**
 * A {@link UserRegistry} read from a file. Users are defined one per line:
 * <pre>
 * name , password , perm1|perm2 , key=val|key=val
 * </pre>
 * The permissions are held on the server as a whole (no resource). The parameters become the
 * principal's attributes, except {@code groups}, which lists the user's groups separated by
 * {@code ;} ({@code groups=sales@bringardner.us;support@bringardner.us}). Each group name seen
 * is a group principal; groups hold no permissions and don't nest. A group with no members is
 * kept on a line of its own:
 * <pre>
 * group: sales@bringardner.us
 * </pre>
 * <p>
 * Groups can be changed through {@link GroupManager} ({@link #createGroup}, {@link #deleteGroup},
 * {@link #addMember}, {@link #removeMember}) when the users were read from a file (not a class
 * path resource). A change rewrites the file, keeping its other lines, comments, permissions and
 * group, and every registry reading the file sees it at its next check. Only users can be
 * members, since groups don't nest here.
 * <p>
 * The file has no ids, so a user's id is {@code user:} followed by its name, and a group's is
 * {@code group:} followed by its name. Renaming a user or group in the file therefore makes a
 * new principal: what the old name owned or was granted elsewhere is not carried over. Names
 * are matched exactly, case included.
 * <p>
 * The password may be plain text (not recommended) or a hash created with
 * {@link #hashPassword(char[])}, e.g.
 * <pre>
 * java -cp ... us.bringardner.parley.net.server.FileUserRegistry mySecret
 * </pre>
 * which prints a value like {PBKDF2}210000:salt:hash to paste into the password field.
 * <p>
 * For SCRAM logins (SCRAM-SHA-1, SCRAM-SHA-256) a hashed password can carry SCRAM credentials
 * after it, each after a {@code ;}:
 * <pre>
 * {PBKDF2}210000:salt:hash;{SCRAM-SHA-256}4096:salt:storedKey:serverKey;{SCRAM-SHA-1}4096:...
 * </pre>
 * {@code FileUserRegistry --scram mySecret} prints such a value ({@link #hashPasswordWithScram(char[])}).
 * A plain text password serves SCRAM too (its credentials are made when first asked for).
 * When a password changes, replace the whole field: SCRAM credentials left from the old password
 * would still let the old password in with SCRAM.
 * SCRAM is offered ({@link #supports(Class, StoredCredentialType)}) only when every user in the
 * file can use it, since a client that picks SCRAM can't fall back to a password for a user who can't.
 * <p>
 * APOP (RFC 1939 section 7) needs the plain text secret: {@link #findStoredCredential} gives it
 * as {@link StoredCredentialType#PLAIN_TEXT} for users whose password is plain text, and APOP is
 * offered when at least one user has one (a POP3 client can still use USER and PASS).
 * <p>
 * A user file on the file system is read again when it changes (checked at most every
 * {@value #PROP_RELOAD_INTERVAL}, default 15s), so users can be added, removed or given new
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
public class FileUserRegistry extends BaseObject implements GroupManager {

	/** Setting (prefix.userFile) naming the user file, a path or a class path resource */
	public static final String PROP_FILE_NAME = "userFile";

	public static final String HASH_PREFIX = "{PBKDF2}";
	/** Starts SCRAM-SHA-256 credentials after a hashed password, see the class comment. @since 1.1.0 */
	public static final String SCRAM_SHA_256_PREFIX = "{SCRAM-SHA-256}";
	/** Starts SCRAM-SHA-1 credentials after a hashed password, see the class comment. @since 1.1.0 */
	public static final String SCRAM_SHA_1_PREFIX = "{SCRAM-SHA-1}";
	/** The login method reported for a password login. @since 2.0.0 */
	public static final String PASSWORD_METHOD = "password";
	/** Groups in the parameters field: {@code groups=sales@bringardner.us;support@bringardner.us}. @since 2.0.0 */
	public static final String PARAMETER_GROUPS = "groups";
	/** Starts the id of a user: {@code user:} and the name. @since 2.0.0 */
	public static final String USER_ID_PREFIX = "user:";
	/** Starts the id of a group: {@code group:} and the name. @since 2.0.0 */
	public static final String GROUP_ID_PREFIX = "group:";
	/** Starts a line that keeps a group, members or not: {@code group: sales@bringardner.us}. @since 2.0.0 */
	public static final String GROUP_LINE_PREFIX = "group:";

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
	/** System property: how long a login waits for its turn before it fails, a duration (default 30s) */
	public static final String PROP_HASH_WAIT = "parley.net.acl.hashWait";
	public static final int DEFAULT_HASH_WAIT_MS = 30000;

	private static volatile int maxConcurrentHashes = Math.max(1, Integer.getInteger(PROP_MAX_CONCURRENT_HASHES,
			Runtime.getRuntime().availableProcessors() / 2));
	private static volatile Semaphore hashPermits = new Semaphore(maxConcurrentHashes, true);
	private static volatile long hashWaitMs = systemDuration(PROP_HASH_WAIT, DEFAULT_HASH_WAIT_MS);
	private static final AtomicInteger hashesInProgress = new AtomicInteger();

	/** A duration system property (see parley-core's Durations), or the default when it isn't set or isn't one */
	private static long systemDuration(String name, long defaultMillis) {
		String v = System.getProperty(name);
		if( v == null || v.trim().isEmpty() ) {
			return defaultMillis;
		}
		try {
			return us.bringardner.parley.core.util.Durations.parse(v);
		} catch (IllegalArgumentException e) {
			System.err.println("Invalid "+name+": "+e.getMessage()+". Using "+us.bringardner.parley.core.util.Durations.format(defaultMillis));
			return defaultMillis;
		}
	}

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
			System.err.println("Usage: FileUserRegistry [--scram] password [password ...]");
			return;
		}
		for (int idx = scram ? 1 : 0; idx < args.length; idx++) {
			char[] pw = args[idx].toCharArray();
			System.out.println(scram ? hashPasswordWithScram(pw) : hashPassword(pw));
		}
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

	/**
	 * A user read from the file, with what stays in the registry: its password, SCRAM
	 * credentials, permissions and groups.
	 */
	private static final class FileUser {

		final ParleyPrincipal principal;
		/** The password field: a {@value FileUserRegistry#HASH_PREFIX} hash or plain text */
		final String secret;
		final List<ParleyPermission> permissions;
		final Set<ParleyPrincipal> groups;
		/** By hash name ("SHA-256"); guarded by this */
		private final Map<String, ScramCredentials> scram;

		FileUser(ParleyPrincipal principal, String secret, Map<String, ScramCredentials> scram,
				List<ParleyPermission> permissions, Set<ParleyPrincipal> groups) {
			this.principal = principal;
			this.secret = secret;
			this.scram = scram;
			this.permissions = Collections.unmodifiableList(permissions);
			this.groups = Collections.unmodifiableSet(groups);
		}

		/** @return true if the password is kept in plain text (so APOP can work) */
		boolean hasPlainSecret() {
			return secret != null && !secret.startsWith(HASH_PREFIX);
		}

		/**
		 * @return the SCRAM credentials for the mechanism's hash: those from the user file, or made
		 * from a plain text password (once); null if there are none
		 */
		synchronized ScramCredentials getScramCredentials(ScramMechanism m) {
			ScramCredentials ret = scram.get(m.getHash());
			if( ret == null && hasPlainSecret() ) {
				// a salt that is the same at every load, so it doesn't tell a real user from
				// an unknown one (whose made up salt never changes)
				ret = m.deriveCredentials(secret, stableSalt(principal.getName(), m.getHash()), ScramMechanism.DEFAULT_ITERATIONS);
				scram.put(m.getHash(), ret);
			}
			return ret;
		}

		/** True if a SCRAM login with this hash can work: credentials kept, or a plain text password. */
		synchronized boolean canUseScram(ScramMechanism m) {
			return scram.containsKey(m.getHash()) || hasPlainSecret();
		}

		boolean checkPassword(char[] password) {
			if( secret == null || password == null ) {
				return false;
			}
			if( secret.startsWith(HASH_PREFIX)) {
				return verifyPassword(password, secret);
			}
			// Plain text password. Constant time compare so response time doesn't leak how much matched.
			return MessageDigest.isEqual(secret.getBytes(StandardCharsets.UTF_8),
					new String(password).getBytes(StandardCharsets.UTF_8));
		}
	}

	/** Everything read from one file, replaced as a whole when the file is read again. */
	private static final class Users {
		final Map<String, FileUser> byName = new LinkedHashMap<String, FileUser>();
		final Map<EntityId, FileUser> byId = new HashMap<EntityId, FileUser>();
		final Map<String, ParleyPrincipal> groupsByName = new LinkedHashMap<String, ParleyPrincipal>();
		final Map<EntityId, ParleyPrincipal> groupsById = new HashMap<EntityId, ParleyPrincipal>();
		boolean hashedPasswords;

		/** @return the group with this name, made when it is first seen */
		ParleyPrincipal group(String name) {
			ParleyPrincipal ret = groupsByName.get(name);
			if( ret == null ) {
				ret = BasicParleyPrincipal.group(EntityId.of(GROUP_ID_PREFIX+name), name);
				groupsByName.put(name, ret);
				groupsById.put(ret.getId(), ret);
			}
			return ret;
		}

		void add(FileUser user) {
			byName.put(user.principal.getName(), user);
			byId.put(user.principal.getId(), user);
		}
	}

	private volatile Users users = new Users();
	/** The users parseLine fills while a file is read (then they replace users) */
	private Users loading;

	/**
	 * System property: how often the user file is checked for changes, a duration, so users added or
	 * changed while a server runs can log in without a restart; 0 never checks. Default 15s.
	 * @since 2.0.0
	 */
	public static final String PROP_RELOAD_INTERVAL = "parley.net.acl.reloadInterval";
	public static final long DEFAULT_RELOAD_INTERVAL_MS = 15_000;
	/** The user file when it was read from the file system (not a class path resource), else null */
	private volatile File sourceFile;
	private volatile long sourceModified;
	private volatile long sourceLength;
	private volatile long lastCheck;
	private static volatile String dummyHash;

	/** A registry with no users, until {@link #initialize(String)} or {@link #initialize(File)} reads some. */
	public FileUserRegistry() {
		super();
	}

	/**
	 * A registry for a server: it reads the server's settings and the file named by the
	 * server's {@value #PROP_FILE_NAME} setting. The server uses this constructor when its
	 * {@value IBaseServer#AUTHENTICATION_PROVIDER_PROPERTY} setting names this class.
	 *
	 * @param server the server that uses the registry
	 * @throws IOException if there is no such setting or the file can't be read
	 * @since 2.0.0
	 */
	public FileUserRegistry(IBaseServer server) throws IOException {
		super();
		useConfigurationOfServer(server);
		readUserFile(server.getPropertyPrefix());
	}

	/** Read the same settings as the server. */
	protected final void useConfigurationOfServer(IBaseServer server) {
		if (server instanceof BaseObject) {
			useConfigurationOf((BaseObject) server);
		}
	}

	/**
	 * Read the users from the file named by the setting {@code serverName.userFile}: a class
	 * path resource, or else a file.
	 *
	 * @param serverName the property prefix of the server
	 * @throws IOException if there is no such setting or the file can't be read
	 */
	public void initialize(String serverName) throws IOException {
		readUserFile(serverName);
	}

	private void readUserFile(String serverName) throws IOException {
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
	 * Read the users from this file (and again whenever it changes, see {@link #PROP_RELOAD_INTERVAL}),
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

	private void load(InputStream in) throws IOException {
		try {
			String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
			List<String> lines = new ArrayList<String>();
			for(String line : text.split("[\n]")) {
				lines.add(line);
			}
			load(lines);
		} finally {
			IoUtils.closeQuietly(in);
		}
	}

	/**
	 * Replace the users with those on these lines, in the user file's format. Blank lines and
	 * lines starting with # are skipped.
	 *
	 * @param lines the lines
	 * @since 2.0.0
	 */
	protected synchronized void load(List<String> lines) {
		Users read = new Users();
		loading = read;
		try {
			for(String line : lines) {
				line = line.trim();
				if( !line.isEmpty()&& !line.startsWith("#")) {
					parseLine(line);
				}
			}
			users = read;
		} finally {
			loading = null;
		}
	}

	/**
	 * Read the user file again if it changed since it was read (checked at most every
	 * {@value #PROP_RELOAD_INTERVAL}). If it can't be read, the users read before stay.
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
		long interval = getDuration(PROP_RELOAD_INTERVAL, DEFAULT_RELOAD_INTERVAL_MS);
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

	/**
	 * Add the user on one line of the user file. While a file is read the user goes with the
	 * others read from it; otherwise it is added to the users in use (for setting a registry up).
	 *
	 * @param line {@code name , password , perm1|perm2 , key=val|key=val}, or a group's
	 *            {@code group: name}
	 */
	protected synchronized void parseLine(String line) {

		if( line.startsWith(GROUP_LINE_PREFIX)) {
			String group = line.substring(GROUP_LINE_PREFIX.length()).trim();
			if( !group.isEmpty()) {
				(loading != null ? loading : users).group(group);
			}
			return;
		}

		String parts[] = line.split("[,]");
		// need at least name and credentials
		if( parts.length < 3) {
			return ;
		}

		// CLean up parts
		for (int idx = 0; idx < parts.length; idx++) {
			parts[idx] = parts[idx].trim();
		}
		Users target = loading != null ? loading : users;

		String name = parts[0];
		//user1  , password   , one|two|three|four|five, key=val|key=val
		String password = parts[1];
		Map<String, ScramCredentials> scram = new HashMap<String, ScramCredentials>();
		if( password.startsWith(HASH_PREFIX)) {
			target.hashedPasswords = true;
			// a hashed password may carry SCRAM credentials: ;{SCRAM-SHA-256}...;{SCRAM-SHA-1}...
			String fields[] = password.split(";");
			password = fields[0].trim();
			for (int idx = 1; idx < fields.length; idx++) {
				String f = fields[idx].trim();
				if( f.startsWith(SCRAM_SHA_256_PREFIX)) {
					putScram(scram, ScramMechanism.SHA_256, name, f.substring(SCRAM_SHA_256_PREFIX.length()));
				} else if( f.startsWith(SCRAM_SHA_1_PREFIX)) {
					putScram(scram, ScramMechanism.SHA_1, name, f.substring(SCRAM_SHA_1_PREFIX.length()));
				} else if( !f.isEmpty()) {
					logError("Ignoring an unknown credential for "+name);
				}
			}
		}

		List<ParleyPermission> permissions = new ArrayList<ParleyPermission>();
		if( !parts[2].isEmpty()) {
			for(String p1 : parts[2].split("[|]")) {
				p1 = p1.trim();
				if( !p1.isEmpty()) {
					permissions.add(new BasicParleyPermission(p1, null));
				}
			}
		}

		Map<String, Object> attributes = new LinkedHashMap<String, Object>();
		Set<ParleyPrincipal> groups = new LinkedHashSet<ParleyPrincipal>();
		if( parts.length> 3 && !parts[3].isEmpty()) {
			for(String a1 : parts[3].split("[|]")) {
				String a2[] = a1.split("[=]");
				if( a2.length == 2) {
					String key = a2[0].trim();
					if( key.equals(PARAMETER_GROUPS)) {
						for (String g : a2[1].split(";")) {
							g = g.trim();
							if( !g.isEmpty()) {
								groups.add(target.group(g));
							}
						}
					} else {
						attributes.put(key, a2[1].trim());
					}
				}
			}
		}

		ParleyPrincipal principal = new BasicParleyPrincipal(EntityId.of(USER_ID_PREFIX+name), name, false, attributes);
		target.add(new FileUser(principal, password, scram, permissions, groups));
	}

	private void putScram(Map<String, ScramCredentials> scram, ScramMechanism m, String user, String text) {
		ScramCredentials credentials = ScramCredentials.parse(text);
		if( credentials == null ) {
			logError("Ignoring malformed SCRAM credentials for "+user);
		} else {
			scram.put(m.getHash(), credentials);
		}
	}

	/** @return the user with this name, after reading the file again if it changed */
	private FileUser user(String name) {
		reloadIfChanged();
		return name == null ? null : users.byName.get(name);
	}

	// ------------------------------------------------------------------ UserRegistry

	/**
	 * Passwords always. SCRAM proofs when every user can use them (and there is at least one
	 * user). Plain text secrets (APOP) when at least one user has a plain text password.
	 */
	@Override
	public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
		reloadIfChanged();
		if( kind == PasswordCredential.class ) {
			return stored == null;
		}
		if( kind != ProofCredential.class || stored == null ) {
			return false;
		}
		Users u = users;
		ScramMechanism m = ScramMechanism.forStoredType(stored);
		if( m != null ) {
			if( u.byName.isEmpty() ) {
				return false;
			}
			for (FileUser user : u.byName.values()) {
				if( !user.canUseScram(m) ) {
					return false;
				}
			}
			return true;
		}
		if( StoredCredentialType.PLAIN_TEXT.equals(stored) ) {
			for (FileUser user : u.byName.values()) {
				if( user.hasPlainSecret() ) {
					return true;
				}
			}
		}
		return false;
	}

	/** Passwords only. An unknown user takes as long to refuse as a known one. */
	@Override
	public AuthenticationResult authenticate(Credential credential) {
		if( !(credential instanceof PasswordCredential) ) {
			return AuthenticationResult.unsupported("FileUserRegistry checks passwords only");
		}
		PasswordCredential passwordCredential = (PasswordCredential) credential;
		char[] password = passwordCredential.getPassword();
		try {
			FileUser user = user(passwordCredential.getUser());
			if( user == null ) {
				authenticateUnknownUser(password);
				return AuthenticationResult.refused("no user "+passwordCredential.getUser());
			}
			if( !user.checkPassword(password) ) {
				return AuthenticationResult.refused("wrong password for "+user.principal.getName());
			}
			return AuthenticationResult.authenticated(user.principal, PASSWORD_METHOD);
		} finally {
			java.util.Arrays.fill(password, '\0');
		}
	}

	/** The same work as checking a hashed password, so the response time doesn't tell which users exist. */
	private void authenticateUnknownUser(char[] password) {
		// Plain text compares take no measurable time, only hashed passwords need matching work.
		if( users.hashedPasswords ) {
			String hash = dummyHash;
			if( hash == null ) {
				hash = dummyHash = hashPassword("not a real password".toCharArray());
			}
			verifyPassword(password == null ? new char[0] : password, hash);
		}
	}

	/**
	 * SCRAM credentials ({@link ScramCredentials}) for the SCRAM kinds, and the password itself
	 * (a String) for {@link StoredCredentialType#PLAIN_TEXT} when it is kept in plain text.
	 */
	@Override
	public StoredCredential findStoredCredential(String name, StoredCredentialType type) {
		FileUser user = user(name);
		if( user == null || type == null ) {
			return null;
		}
		ScramMechanism m = ScramMechanism.forStoredType(type);
		if( m != null ) {
			ScramCredentials credentials = user.getScramCredentials(m);
			return credentials == null ? null : new StoredCredential(type, credentials);
		}
		if( StoredCredentialType.PLAIN_TEXT.equals(type) && user.hasPlainSecret() ) {
			return new StoredCredential(type, user.secret);
		}
		return null;
	}

	/** A user with this name, else a group with this name, else null. */
	@Override
	public ParleyPrincipal findPrincipal(String name) {
		FileUser user = user(name);
		if( user != null ) {
			return user.principal;
		}
		return name == null ? null : users.groupsByName.get(name);
	}

	@Override
	public ParleyPrincipal findPrincipal(EntityId id) {
		reloadIfChanged();
		Users u = users;
		FileUser user = u.byId.get(id);
		if( user != null ) {
			return user.principal;
		}
		return u.groupsById.get(id);
	}

	/**
	 * Allowed when the logged-in user's line lists a permission that covers the one needed
	 * ({@link ParleyPermission#implies}). The permissions in the file are on the server as a
	 * whole, so a check about a resource is denied; groups grant nothing, and nobody logged in
	 * holds nothing.
	 */
	@Override
	public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
			ProtectedResource resource) {
		ParleyPrincipal principal = requester.getPrincipal();
		if( principal == null ) {
			return AuthorizationResult.denied("nobody logged in");
		}
		for (ParleyPermission permission : findPermissions(requester, principal, resource)) {
			if( permission.implies(needed) ) {
				return AuthorizationResult.allowed(principal.getName()+" holds "+permission);
			}
		}
		return AuthorizationResult.denied(principal.getName()+" holds nothing that covers "+needed);
	}

	/** The groups the user's line names, in order; groups don't nest, so a group is in none. */
	@Override
	public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) {
		reloadIfChanged();
		FileUser user = principal == null ? null : users.byId.get(principal.getId());
		if( user == null ) {
			return new LinkedHashSet<ParleyPrincipal>();
		}
		return new LinkedHashSet<ParleyPrincipal>(user.groups);
	}

	/** The users whose lines name this group, in the file's order. */
	@Override
	public Set<ParleyPrincipal> findMembers(ParleyPrincipal group) {
		reloadIfChanged();
		Users u = users;
		Set<ParleyPrincipal> ret = new LinkedHashSet<ParleyPrincipal>();
		if( group == null || !u.groupsById.containsKey(group.getId())) {
			return ret;
		}
		for (FileUser user : u.byName.values()) {
			for (ParleyPrincipal g : user.groups) {
				if( g.getId().equals(group.getId())) {
					ret.add(user.principal);
				}
			}
		}
		return ret;
	}

	// ------------------------------------------------------------------ GroupManager

	/**
	 * Adds a {@code group: name} line.
	 *
	 * @throws IllegalArgumentException also for a name with a character the file uses to
	 *             separate fields ({@code , ; | =}), a line break, or space at either end
	 */
	@Override
	public synchronized ParleyPrincipal createGroup(String name) throws UserRegistryUnavailableException {
		checkGroupName(name);
		List<String> lines = readForChange();
		Users u = users;
		if( u.byName.containsKey(name) || u.groupsByName.containsKey(name)) {
			throw new IllegalArgumentException("The name "+name+" is taken");
		}
		lines.add(GROUP_LINE_PREFIX+" "+name);
		writeChange(lines);
		return users.groupsByName.get(name);
	}

	/** Removes the group's {@code group:} lines and its name from every user's line. */
	@Override
	public synchronized boolean deleteGroup(ParleyPrincipal group) throws UserRegistryUnavailableException {
		if( group == null ) {
			return false;
		}
		List<String> lines = readForChange();
		ParleyPrincipal stored = users.groupsById.get(group.getId());
		if( stored == null ) {
			return false;
		}
		String name = stored.getName();
		List<String> changed = new ArrayList<String>();
		for (String line : lines) {
			String t = line.trim();
			if( isGroupLine(t, name)) {
				continue;
			}
			List<String> groups = isUserLine(t) ? groupsOn(t) : null;
			if( groups != null && groups.remove(name)) {
				changed.add(withGroups(line, groups));
			} else {
				changed.add(line);
			}
		}
		writeChange(changed);
		return true;
	}

	/** Adds the group's name to the user's line (the last line with that name, the one in use). */
	@Override
	public synchronized boolean addMember(ParleyPrincipal group, ParleyPrincipal member) throws UserRegistryUnavailableException {
		if( group == null || member == null ) {
			throw new IllegalArgumentException("A group and a member are needed");
		}
		List<String> lines = readForChange();
		Users u = users;
		ParleyPrincipal storedGroup = u.groupsById.get(group.getId());
		if( storedGroup == null ) {
			throw new IllegalArgumentException("No group "+group.getName()+" in "+sourceFile);
		}
		FileUser user = u.byId.get(member.getId());
		if( user == null ) {
			if( u.groupsById.containsKey(member.getId())) {
				throw new IllegalArgumentException("Groups don't nest in a user file: "+member.getName()+" is a group");
			}
			throw new IllegalArgumentException("No user "+member.getName()+" in "+sourceFile);
		}
		if( user.groups.contains(storedGroup)) {
			return false;
		}
		int index = lineOf(lines, user.principal.getName());
		List<String> groups = groupsOn(lines.get(index).trim());
		groups.add(storedGroup.getName());
		lines.set(index, withGroups(lines.get(index), groups));
		writeChange(lines);
		return true;
	}

	/**
	 * Takes the group's name off the user's line. When that leaves a group with no members and
	 * no {@code group:} line, one is added, so the group stays.
	 */
	@Override
	public synchronized boolean removeMember(ParleyPrincipal group, ParleyPrincipal member) throws UserRegistryUnavailableException {
		if( group == null || member == null ) {
			return false;
		}
		List<String> lines = readForChange();
		Users u = users;
		ParleyPrincipal storedGroup = u.groupsById.get(group.getId());
		FileUser user = u.byId.get(member.getId());
		if( storedGroup == null || user == null || !user.groups.contains(storedGroup)) {
			return false;
		}
		String name = storedGroup.getName();
		int index = lineOf(lines, user.principal.getName());
		List<String> groups = groupsOn(lines.get(index).trim());
		groups.remove(name);
		lines.set(index, withGroups(lines.get(index), groups));
		boolean kept = false;
		for (String line : lines) {
			String t = line.trim();
			if( isGroupLine(t, name) || (isUserLine(t) && groupsOn(t).contains(name))) {
				kept = true;
				break;
			}
		}
		if( !kept ) {
			lines.add(GROUP_LINE_PREFIX+" "+name);
		}
		writeChange(lines);
		return true;
	}

	private static void checkGroupName(String name) {
		if( name == null || name.trim().isEmpty()) {
			throw new IllegalArgumentException("A group needs a name");
		}
		if( !name.equals(name.trim()) || name.startsWith("#")) {
			throw new IllegalArgumentException("A group's name can't start with # or space, or end with space: '"+name+"'");
		}
		for (char c : name.toCharArray()) {
			if( c == ',' || c == ';' || c == '|' || c == '=' || c == '\n' || c == '\r') {
				throw new IllegalArgumentException("A group's name can't hold '"+c+"' in a user file: "+name);
			}
		}
	}

	/** @return true for a {@code group: name} line of this group (trimmed line) */
	private static boolean isGroupLine(String trimmed, String name) {
		return trimmed.startsWith(GROUP_LINE_PREFIX)
				&& trimmed.substring(GROUP_LINE_PREFIX.length()).trim().equals(name);
	}

	/** @return true for a line parseLine reads as a user (trimmed line) */
	private static boolean isUserLine(String trimmed) {
		return !trimmed.isEmpty() && !trimmed.startsWith("#") && !trimmed.startsWith(GROUP_LINE_PREFIX)
				&& trimmed.split("[,]").length >= 3;
	}

	/** @return the index of the last user line with this name, the one in use */
	private static int lineOf(List<String> lines, String user) throws UserRegistryUnavailableException {
		for (int idx = lines.size()-1; idx >= 0; idx--) {
			String t = lines.get(idx).trim();
			if( isUserLine(t) && t.split("[,]")[0].trim().equals(user)) {
				return idx;
			}
		}
		// the file changed under us between reading it and now
		throw new UserRegistryUnavailableException("The user file no longer has a line for "+user);
	}

	/** @return the groups a user line names, in order, in a list that may be changed */
	private static List<String> groupsOn(String trimmed) {
		List<String> ret = new ArrayList<String>();
		String parts[] = trimmed.split("[,]");
		if( parts.length > 3 ) {
			for (String a1 : parts[3].split("[|]")) {
				String a2[] = a1.split("[=]");
				if( a2.length == 2 && a2[0].trim().equals(PARAMETER_GROUPS)) {
					for (String g : a2[1].split(";")) {
						g = g.trim();
						if( !g.isEmpty() && !ret.contains(g)) {
							ret.add(g);
						}
					}
				}
			}
		}
		return ret;
	}

	/**
	 * @return the user line with its {@code groups} parameter set to these groups (removed when
	 * there are none); the other fields and parameters are kept as they are
	 */
	static String withGroups(String line, List<String> groups) {
		String parts[] = line.split("[,]", -1);
		StringBuilder params = new StringBuilder();
		if( parts.length > 3 ) {
			for (String a1 : parts[3].split("[|]")) {
				String a2[] = a1.split("[=]");
				if( a1.trim().isEmpty() || (a2.length >= 1 && a2[0].trim().equals(PARAMETER_GROUPS))) {
					continue;
				}
				if( params.length() > 0 ) {
					params.append("|");
				}
				params.append(a1.trim());
			}
		}
		if( !groups.isEmpty()) {
			if( params.length() > 0 ) {
				params.append("|");
			}
			params.append(PARAMETER_GROUPS).append("=").append(String.join(";", groups));
		}
		StringBuilder ret = new StringBuilder();
		for (int idx = 0; idx < 3; idx++) {
			if( idx > 0 ) {
				ret.append(",");
			}
			ret.append(parts[idx]);
		}
		// the third field ends where its text does, then the file's " , " before the parameters
		String fields = ret.toString().replaceAll("\\s+$", "");
		ret.setLength(0);
		ret.append(fields);
		if( params.length() > 0 || parts.length > 4 ) {
			// a field after the parameters keeps its place, so an empty parameters field stays
			ret.append(" , ").append(params);
		}
		for (int idx = 4; idx < parts.length; idx++) {
			ret.append(",").append(parts[idx]);
		}
		return ret.toString();
	}

	/**
	 * Reads the user file again if it changed, then returns its lines as they are, for a change.
	 *
	 * @throws UnsupportedOperationException when the users weren't read from a file
	 */
	private List<String> readForChange() throws UserRegistryUnavailableException {
		File f = sourceFile;
		if( f == null ) {
			throw new UnsupportedOperationException("The users weren't read from a file (a class path resource), so they can't be changed");
		}
		reload(f, System.currentTimeMillis());
		try {
			String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
			List<String> lines = new ArrayList<String>();
			for (String line : text.split("\r?\n", -1)) {
				lines.add(line);
			}
			// split leaves one empty string after the last line break
			if( !lines.isEmpty() && lines.get(lines.size()-1).isEmpty()) {
				lines.remove(lines.size()-1);
			}
			return lines;
		} catch (IOException e) {
			throw new UserRegistryUnavailableException("Can't read the user file "+f, e);
		}
	}

	/**
	 * Writes the lines through a temporary file in the same folder, giving it the old file's
	 * permissions and group first, then reads the file again.
	 */
	private void writeChange(List<String> lines) throws UserRegistryUnavailableException {
		File f = sourceFile;
		StringBuilder text = new StringBuilder();
		for (String line : lines) {
			text.append(line).append('\n');
		}
		Path target = f.toPath().toAbsolutePath();
		Path folder = target.getParent();
		if( folder == null ) {
			throw new UserRegistryUnavailableException("The user file "+f+" has no folder to write in");
		}
		try {
			// a name of its own, so another writer of the file (an application's own page) can't collide
			Path tmp = Files.createTempFile(folder, "."+f.getName()+".", ".tmp");
			try {
				Files.write(tmp, text.toString().getBytes(StandardCharsets.UTF_8));
				copyPermissions(target, tmp);
				try {
					Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
				} catch (IOException e) {
					Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
				}
			} finally {
				Files.deleteIfExists(tmp);
			}
		} catch (IOException e) {
			throw new UserRegistryUnavailableException("Can't change the user file "+f, e);
		}
		// read it now, whatever the time stamps say (a change within the same second, same length)
		synchronized (this) {
			sourceModified = -1;
		}
		reload(f, System.currentTimeMillis());
	}

	/** Gives the new file the old one's permissions and group, where the file system has them. */
	private void copyPermissions(Path original, Path copy) {
		PosixFileAttributeView from = Files.getFileAttributeView(original, PosixFileAttributeView.class);
		PosixFileAttributeView to = Files.getFileAttributeView(copy, PosixFileAttributeView.class);
		if( from == null || to == null ) {
			return; // Windows: the folder's permissions apply to the new file
		}
		try {
			PosixFileAttributes a = from.readAttributes();
			to.setPermissions(a.permissions());
			if( !a.group().equals(to.readAttributes().group())) {
				to.setGroup(a.group());
			}
		} catch (IOException | SecurityException e) {
			logError("Can't give the changed user file "+original+" its permissions or group again: "+e.getMessage());
		}
	}

	/**
	 * The user's permissions, which are on the server as a whole: empty for a resource and for
	 * a group.
	 */
	public Collection<ParleyPermission> findPermissions(Requester requester, ParleyPrincipal holder,
			ProtectedResource resource) {
		FileUser user = holder == null || resource != null ? null : users.byId.get(holder.getId());
		if( user == null ) {
			return new ArrayList<ParleyPermission>();
		}
		return new ArrayList<ParleyPermission>(user.permissions);
	}
}
