package us.bringardner.parley.net.server;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * The settings of a {@link ServerLauncher}: settings files read in order (a later file wins),
 * the JVM's own system properties ({@code java -Dname=value}), which win over the files, and the
 * command line, which wins over both. Every setting becomes a system property, where the servers
 * read their settings when they are made. {@link #apply()} can be called again (after a file
 * changed): settings a file no longer has are removed, unless the JVM or command line set them.
 *
 * @since 2.0.0
 */
public final class LaunchSettings {

	private final Set<String> jvm;
	private final Properties commandLine;
	private final List<File> files = new ArrayList<>();
	private final Set<File> required = new HashSet<>();
	/** The settings the files set, and their values */
	private final Map<String, String> fromFiles = new LinkedHashMap<>();

	/**
	 * @param commandLine the command line's settings ({@code -Dname=value} or {@code name value})
	 */
	public LaunchSettings(Properties commandLine) {
		this.commandLine = commandLine;
		this.jvm = new HashSet<>(System.getProperties().stringPropertyNames());
		this.jvm.removeAll(commandLine.stringPropertyNames());
	}

	/** Parse a command line: {@code -Dname=value} or {@code name value} pairs. */
	public static Properties parse(String[] args) {
		Properties p = new Properties();
		for (int idx = 0; idx < args.length; idx++) {
			if (args[idx].startsWith("-D")) {
				String[] tmp = args[idx].substring(2).split("=", 2);
				if (tmp.length == 2) {
					p.setProperty(tmp[0], tmp[1]);
				} else {
					System.out.println("Invalid arg = " + args[idx]);
				}
			} else if (idx + 1 < args.length) {
				p.setProperty(args[idx++], args[idx]);
			} else {
				System.out.println("Invalid arg = " + args[idx]);
			}
		}
		return p;
	}

	/**
	 * The value of a setting before the files are read: the command line's, else the JVM's, else null
	 */
	public String early(String name) {
		String v = commandLine.getProperty(name);
		return v != null ? v : (jvm.contains(name) ? System.getProperty(name) : null);
	}

	/**
	 * Read this file too (after those added before, so it wins over them).
	 *
	 * @param mustExist true for a file someone named (an error if it isn't there); false for a
	 *                  default file, which is skipped when it isn't there
	 */
	public synchronized void addFile(File f, boolean mustExist) {
		File a = f.getAbsoluteFile();
		if (!files.contains(a)) {
			files.add(a);
		}
		if (mustExist) {
			required.add(a);
		}
	}

	/** The files, in order, whether they exist or not */
	public synchronized List<File> getFiles() {
		return Collections.unmodifiableList(new ArrayList<>(files));
	}

	/**
	 * Read the files and set the system properties.
	 *
	 * @throws IOException if a named file can't be read (nothing is changed then)
	 */
	public synchronized void apply() throws IOException {
		Map<String, String> merged = new LinkedHashMap<>();
		for (File f : files) {
			if (!f.isFile()) {
				if (required.contains(f)) {
					throw new IOException("Can't read the settings file " + f);
				}
				continue;
			}
			Properties p = ServerMain.load(f);
			for (String name : p.stringPropertyNames()) {
				merged.put(name, p.getProperty(name));
			}
		}
		for (String name : fromFiles.keySet()) {
			if (!merged.containsKey(name) && !jvm.contains(name) && !commandLine.containsKey(name)) {
				System.clearProperty(name); // no longer in a file
			}
		}
		fromFiles.clear();
		for (Map.Entry<String, String> e : merged.entrySet()) {
			if (!jvm.contains(e.getKey()) && !commandLine.containsKey(e.getKey())) {
				System.setProperty(e.getKey(), e.getValue());
				fromFiles.put(e.getKey(), e.getValue());
			}
		}
		for (String name : commandLine.stringPropertyNames()) {
			System.setProperty(name, commandLine.getProperty(name));
		}
	}

	/** Print the command line's settings, and which files were read (no secret values). */
	public synchronized void print(String serverName) {
		System.out.println("\nStarting " + serverName);
		for (String name : commandLine.stringPropertyNames()) {
			System.out.println("\t" + name + "=" + ServerMain.printable(name, commandLine.getProperty(name)));
		}
		for (File f : files) {
			if (f.isFile()) {
				System.out.println("Loaded properties from " + f);
			}
		}
	}
}
