package us.bringardner.parley.net.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import us.bringardner.parley.files.FileSource;

/**
 * The setting names the Parley modules on the class path read, so a server can warn at start-up
 * about a setting nothing will read: a {@code parley.*} name no module lists (a typo silently
 * gives the default, since every name is looked up exactly), or a 1.x name (2.0.0 no longer reads
 * {@code JPop3.port}, {@code Pop3Server.port}, ...).
 * <p>
 * Each module jar lists the names its own code reads in {@value #RESOURCE}, one per line
 * ({@code #} starts a comment):
 * <pre>
 * parley.mail.root                          a name
 * parley.mail.{pop3,pop3s}.requireTls       one of several in a segment
 * parley.mail.*.configFile                  any one segment
 * parley.core.log.level.**                  one or more segments at the end
 * renamed JPop3.port parley.mail.pop3.port  a 1.x name and what it is now
 * prefix parley.mail.pop3s                  a server's prefix (a server module's list)
 * &lt;server&gt;.keyStoreName                     a name under every server's prefix (the framework's)
 * </pre>
 * Every list on the class path is read, so a library's names are known wherever the library is
 * loaded, and only there.
 *
 * @since 2.0.0
 */
public final class KnownSettings {

	/** Where a module jar lists its setting names */
	public static final String RESOURCE = "META-INF/parley/settings.list";

	private static final String RENAMED = "renamed";
	private static final String PREFIX = "prefix";
	private static final String SERVER = "<server>";
	/** A name that looks like a setting: parley, a lower case family, then any segments */
	private static final Pattern SETTING = Pattern.compile("parley\\.[a-z][a-z0-9]*(\\.[A-Za-z][A-Za-z0-9]*)*");
	/**
	 * 1.x names: JPop3.*, Pop3Server.*, FileSource.* (not us.bringardner.*: a client's settings
	 * still have its class name as their prefix)
	 */
	private static final Pattern OLD = Pattern.compile("(J[A-Z][A-Za-z0-9]*|[A-Z][A-Za-z0-9]*Server|FileSource)\\..+");

	private final List<Pattern> names = new ArrayList<>();
	private final List<String> lines = new ArrayList<>();
	private final Map<String, String> renamed = new LinkedHashMap<>();
	private final List<String> prefixes = new ArrayList<>();
	/** The rest of each &lt;server&gt; line (".keyStoreName"), as given */
	private final List<String> serverLines = new ArrayList<>();
	/** The &lt;server&gt; lines with every prefix, made again when either changes */
	private List<Pattern> serverNames;

	private KnownSettings() {
	}

	/** The lists on this class loader's class path */
	public static KnownSettings load(ClassLoader loader) throws IOException {
		KnownSettings ret = new KnownSettings();
		Enumeration<URL> e = loader.getResources(RESOURCE);
		while (e.hasMoreElements()) {
			URL u = e.nextElement();
			try (Reader r = new InputStreamReader(u.openStream(), StandardCharsets.UTF_8)) {
				ret.read(r, u.toString());
			}
		}
		return ret;
	}

	/** The lists on the class path of this class's loader (and, if different, the thread's) */
	public static KnownSettings load() throws IOException {
		KnownSettings ret = load(KnownSettings.class.getClassLoader());
		ClassLoader t = Thread.currentThread().getContextClassLoader();
		if (t != null && t != KnownSettings.class.getClassLoader()) {
			KnownSettings more = load(t);
			for (int i = 0; i < more.lines.size(); i++) {
				if (!ret.lines.contains(more.lines.get(i))) {
					ret.lines.add(more.lines.get(i));
					ret.names.add(more.names.get(i));
				}
			}
			ret.renamed.putAll(more.renamed);
			for (String p : more.prefixes) {
				ret.addPrefix(p);
			}
			for (String l : more.serverLines) {
				if (!ret.serverLines.contains(l)) {
					ret.serverLines.add(l);
				}
			}
			ret.serverNames = null;
		}
		return ret;
	}

	/** A list's lines, for tests */
	public static KnownSettings of(String... lines) {
		KnownSettings ret = new KnownSettings();
		try {
			ret.read(new StringReader(String.join("\n", lines)), "(given)");
		} catch (IOException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		return ret;
	}

	private void read(Reader in, String where) throws IOException {
		BufferedReader r = new BufferedReader(in);
		String line;
		int n = 0;
		while ((line = r.readLine()) != null) {
			n++;
			int hash = line.indexOf('#');
			if (hash >= 0) {
				line = line.substring(0, hash);
			}
			line = line.trim();
			if (line.isEmpty()) {
				continue;
			}
			String[] words = line.split("\\s+");
			if (words[0].equals(PREFIX)) {
				if (words.length != 2 || !isSettingPrefix(words[1])) {
					throw new IOException(where + ":" + n + ": 'prefix parley.FAMILY[.NAME]', not '" + line + "'");
				}
				addPrefix(words[1]);
			} else if (words.length == 1 && line.startsWith(SERVER + ".")) {
				String rest = line.substring(SERVER.length());
				pattern("x" + rest, where + ":" + n); // checked here, made with the prefixes later
				if (!serverLines.contains(rest)) {
					serverLines.add(rest);
					serverNames = null;
				}
			} else if (words[0].equals(RENAMED)) {
				if (words.length != 3) {
					throw new IOException(where + ":" + n + ": 'renamed OLD NEW', not '" + line + "'");
				}
				renamed.put(words[1], words[2]);
			} else if (words.length == 1) {
				if (!lines.contains(line)) {
					lines.add(line);
					names.add(pattern(line, where + ":" + n));
				}
			} else {
				throw new IOException(where + ":" + n + ": one name per line, not '" + line + "'");
			}
		}
	}

	private static boolean isSettingPrefix(String p) {
		return p.matches("parley(\\.[a-z][a-z0-9]*)+");
	}

	/**
	 * Add a server's prefix (a server made in code with a prefix no list has, a test's say): the
	 * &lt;server&gt; names under it are known too.
	 */
	public KnownSettings addPrefix(String prefix) {
		if (!prefixes.contains(prefix)) {
			prefixes.add(prefix);
			serverNames = null;
		}
		return this;
	}

	/** @return the servers' prefixes the lists name */
	public List<String> prefixes() {
		return Collections.unmodifiableList(prefixes);
	}

	private synchronized List<Pattern> serverNames() {
		if (serverNames == null) {
			List<Pattern> l = new ArrayList<>();
			if (!prefixes.isEmpty()) {
				StringBuilder alt = new StringBuilder("(");
				for (int i = 0; i < prefixes.size(); i++) {
					alt.append(i > 0 ? "|" : "").append(Pattern.quote(prefixes.get(i)));
				}
				alt.append(")");
				for (String rest : serverLines) {
					try {
						String re = pattern("x" + rest, "").pattern();
						l.add(Pattern.compile(alt + re.substring(re.indexOf("\\."))));
					} catch (IOException e) {
						// checked when it was read
					}
				}
			}
			serverNames = l;
		}
		return serverNames;
	}

	/** A list line as a regular expression for the whole name */
	static Pattern pattern(String line, String where) throws IOException {
		String[] segments = line.split("\\.", -1);
		StringBuilder re = new StringBuilder();
		for (int i = 0; i < segments.length; i++) {
			String s = segments[i];
			if (i > 0) {
				re.append("\\.");
			}
			if (s.isEmpty()) {
				throw new IOException(where + ": an empty segment in '" + line + "'");
			} else if (s.equals("**")) {
				if (i != segments.length - 1) {
					throw new IOException(where + ": '**' only as the last segment, not in '" + line + "'");
				}
				re.append("[^.]+(\\.[^.]+)*");
			} else if (s.equals("*")) {
				re.append("[^.]+");
			} else if (s.startsWith("{") && s.endsWith("}") && s.length() > 2) {
				re.append("(");
				String[] alts = s.substring(1, s.length() - 1).split(",");
				for (int a = 0; a < alts.length; a++) {
					if (a > 0) {
						re.append("|");
					}
					re.append(Pattern.quote(alts[a].trim()));
				}
				re.append(")");
			} else if (s.matches("[A-Za-z0-9_-]+")) {
				re.append(Pattern.quote(s));
			} else {
				throw new IOException(where + ": '" + s + "' is not a name, '*', '**' or '{a,b}' in '" + line + "'");
			}
		}
		return Pattern.compile(re.toString());
	}

	/** @return true if a list on the class path has this name */
	public boolean isKnown(String name) {
		for (Pattern p : names) {
			if (p.matcher(name).matches()) {
				return true;
			}
		}
		for (Pattern p : serverNames()) {
			if (p.matcher(name).matches()) {
				return true;
			}
		}
		return false;
	}

	/** @return the name a 1.x (or renamed) setting has now, or null if no list says */
	public String renamedTo(String name) {
		return renamed.get(name);
	}

	/** @return true if name looks like a Parley setting: {@code parley.<family>.<name>...} */
	public static boolean isSettingName(String name) {
		return SETTING.matcher(name).matches();
	}

	/** @return true if name looks like a 1.x setting name: JPop3.*, Pop3Server.*, us.bringardner.* ... */
	public static boolean looksOld(String name) {
		return OLD.matcher(name).matches();
	}

	/**
	 * A warning for each setting nothing will read: a {@code parley.*} name no list has, or a 1.x
	 * name (with its new name when a list knows it). Other names (java.*, javax.*, a JVM's own)
	 * aren't Parley's and aren't looked at.
	 *
	 * @param bySource the names set, by where they were set ("/etc/parley/parley-mail.properties",
	 *                 "the command line", ...), in the order to report them
	 * @return the warnings, one per name and source
	 */
	public List<String> check(Map<String, ? extends Collection<String>> bySource) {
		List<String> ret = new ArrayList<>();
		for (Map.Entry<String, ? extends Collection<String>> e : bySource.entrySet()) {
			for (String name : new TreeSet<>(e.getValue())) {
				String w = warning(name);
				if (w != null) {
					ret.add(name + " (" + e.getKey() + ") " + w);
				}
			}
		}
		return ret;
	}

	/**
	 * Print a warning to System.err for each setting nothing will read, as {@link #check(Map)}
	 * finds them with the lists on the class path. Only a warning: the caller goes on as it would.
	 *
	 * @param who the program, at the start of each line (e.g. the launcher's name)
	 * @return the warnings printed
	 */
	public static List<String> warn(String who, Map<String, ? extends Collection<String>> bySource) {
		KnownSettings known;
		try {
			known = load();
		} catch (IOException | RuntimeException e) {
			System.err.println(who + ": can't read the lists of known settings: " + e.getMessage());
			return Collections.emptyList();
		}
		List<String> ret = known.check(bySource);
		for (String w : ret) {
			System.err.println(who + ": warning: " + w);
		}
		return ret;
	}

	/** What's wrong with this name, or null if nothing is (or it isn't Parley's) */
	private String warning(String name) {
		String now = renamed.get(name);
		if (now != null) {
			return "is no longer read: since 2.0.0 it is " + now;
		}
		if (name.startsWith("parley.")) {
			return isKnown(name) ? null : "is not a setting any Parley module here reads: check the spelling";
		}
		if (looksOld(name)) {
			return "looks like a 1.x setting, which 2.0.0 no longer reads: see the module's CHANGELOG for its new name";
		}
		return null;
	}

	/**
	 * @return the {@code parley.*} names here that no list has (or marks as renamed), sorted: for a
	 *         module's test that its list is complete
	 */
	public List<String> undeclared(Collection<String> settingNames) {
		List<String> ret = new ArrayList<>();
		for (String n : new TreeSet<>(settingNames)) {
			if (n.startsWith("parley.") && !isKnown(n) && !isPrefix(n) && !renamed.containsKey(n)) {
				ret.add(n);
			}
		}
		return ret;
	}

	/**
	 * A server's prefix, or the start of one (parley.mail), or of a renamed name (a dropped server's
	 * prefix): a constant for one, not a setting
	 */
	private boolean isPrefix(String n) {
		for (String p : prefixes) {
			if (p.equals(n) || p.startsWith(n + ".")) {
				return true;
			}
		}
		for (String old : renamed.keySet()) {
			if (old.startsWith(n + ".")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Every {@code static final String} constant in the jar (or classes folder) that holds the given
	 * class, whose value looks like a Parley setting name ({@link #isSettingName(String)}), for a
	 * module's test that its list has every name its code spells out.
	 */
	public static List<String> settingConstants(Class<?> inModule) throws IOException {
		// a local file (FileProxy, To-Do 18.12): the JVM loaded the classes from it
		FileSource where;
		try {
			where = FileSource.of(inModule.getProtectionDomain().getCodeSource().getLocation().toURI());
		} catch (URISyntaxException e) {
			throw new IOException(e);
		}
		List<String> classes = new ArrayList<>();
		if (where.isDirectory()) {
			collect(where, "", classes);
		} else {
			// (only JarFile needs the java.io.File)
			try (JarFile jar = new JarFile(where.toFile())) {
				for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();) {
					String n = e.nextElement().getName();
					if (n.endsWith(".class") && !n.contains("-")) {
						classes.add(n.substring(0, n.length() - 6).replace('/', '.'));
					}
				}
			}
		}
		TreeSet<String> ret = new TreeSet<>();
		ClassLoader loader = inModule.getClassLoader();
		for (String c : classes) {
			Class<?> k;
			try {
				k = Class.forName(c, false, loader);
			} catch (Throwable t) {
				continue;
			}
			Field[] fields;
			try {
				fields = k.getDeclaredFields();
			} catch (Throwable t) {
				continue;
			}
			for (Field f : fields) {
				int m = f.getModifiers();
				if (f.getType() != String.class || !Modifier.isStatic(m) || !Modifier.isFinal(m)) {
					continue;
				}
				try {
					f.setAccessible(true);
					Object v = f.get(null);
					if (v instanceof String && isSettingName((String) v)) {
						ret.add((String) v);
					}
				} catch (Throwable t) {
					// a class that can't be initialized here: skipped
				}
			}
		}
		return Collections.unmodifiableList(new ArrayList<>(ret));
	}

	private static void collect(FileSource dir, String pkg, List<String> into) throws IOException {
		FileSource[] files = dir.listFiles();
		if (files == null) {
			return;
		}
		for (FileSource f : files) {
			if (f.isDirectory()) {
				collect(f, pkg + f.getName() + ".", into);
			} else if (f.getName().endsWith(".class") && !f.getName().contains("-")) {
				into.add(pkg + f.getName().substring(0, f.getName().length() - 6));
			}
		}
	}

	/**
	 * Properties that remember every name asked for, for a module's test that its list has every
	 * name its servers read: give a server one as its configuration, run it, then check
	 * {@link #asked()}.
	 */
	public static class RecordingProperties extends java.util.Properties {
		private static final long serialVersionUID = 1L;
		private final java.util.Set<String> asked = Collections.synchronizedSet(new TreeSet<>());

		public RecordingProperties() {
		}

		public RecordingProperties(java.util.Properties values) {
			if (values != null) {
				for (String n : values.stringPropertyNames()) {
					setProperty(n, values.getProperty(n));
				}
			}
		}

		@Override
		public String getProperty(String key) {
			asked.add(key);
			return super.getProperty(key);
		}

		@Override
		public String getProperty(String key, String defaultValue) {
			asked.add(key);
			return super.getProperty(key, defaultValue);
		}

		@Override
		public synchronized Object get(Object key) {
			if (key instanceof String) {
				asked.add((String) key);
			}
			return super.get(key);
		}

		@Override
		public synchronized boolean containsKey(Object key) {
			if (key instanceof String) {
				asked.add((String) key);
			}
			return super.containsKey(key);
		}

		/** @return every name asked for so far, sorted */
		public List<String> asked() {
			synchronized (asked) {
				return new ArrayList<>(asked);
			}
		}

	}
}
