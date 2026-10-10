package us.bringardner.parley.net.capability;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import us.bringardner.parley.net.client.ICommandResponse;

/**
 * The capabilities one end of a session has announced, kept in the order they were added.
 * <p>
 * A server builds one (or resolves one from a {@link CapabilityRegistry}) and renders it the
 * way its protocol lists capabilities; a client parses what the server sent and asks
 * {@link #has(String)} before using an extension.
 * <pre>
 *   SMTP EHLO  250-SIZE 1000        toLines()        lines, one capability each
 *   POP3 CAPA  SASL PLAIN           toLines()
 *   FTP  FEAT   MLST size*;type*    toLines()
 *   IMAP       AUTH=PLAIN STARTTLS  toInline()       one line, parameters joined with '='
 * </pre>
 * Adding a name that is already present adds its parameters to the existing capability.
 * Not thread safe.
 */
public class CapabilitySet implements Iterable<Capability> {

	private final Map<String, Capability> byName = new LinkedHashMap<>();

	/**
	 * Add a capability, or add the parameters to the one of that name.
	 *
	 * @return this, for chaining
	 */
	public CapabilitySet add(String name, String... params) {
		return add(new Capability(name, params));
	}

	/** @see #add(String, String...) */
	public CapabilitySet add(Capability capability) {
		String key = key(capability.getName());
		Capability old = byName.get(key);
		if (old == null) {
			byName.put(key, capability);
		} else {
			List<String> merged = new ArrayList<>(old.getParams());
			for (String p : capability.getParams()) {
				if (!old.hasParam(p)) {
					merged.add(p);
				}
			}
			byName.put(key, new Capability(old.getName(), merged));
		}
		return this;
	}

	/** Add the capability only if the condition holds. */
	public CapabilitySet addIf(boolean condition, String name, String... params) {
		return condition ? add(name, params) : this;
	}

	public CapabilitySet addAll(Iterable<Capability> capabilities) {
		for (Capability c : capabilities) {
			add(c);
		}
		return this;
	}

	/** @return true if something was removed */
	public boolean remove(String name) {
		return byName.remove(key(name)) != null;
	}

	/** @return true if the capability is present, whatever its parameters */
	public boolean has(String name) {
		return byName.containsKey(key(name));
	}

	/** @return true if the capability is present and has the parameter (ignoring case) */
	public boolean has(String name, String param) {
		Capability c = get(name);
		return c != null && c.hasParam(param);
	}

	/** @return the capability, or null */
	public Capability get(String name) {
		return byName.get(key(name));
	}

	/** @return the parameters of the capability, empty if it is absent or has none */
	public List<String> getParams(String name) {
		Capability c = get(name);
		return c == null ? Collections.<String>emptyList() : c.getParams();
	}

	/** @return the capabilities in the order they were added */
	public Collection<Capability> getAll() {
		return Collections.unmodifiableCollection(byName.values());
	}

	public int size() {
		return byName.size();
	}

	public boolean isEmpty() {
		return byName.isEmpty();
	}

	@Override
	public Iterator<Capability> iterator() {
		return getAll().iterator();
	}

	/**
	 * @return one "NAME p1 p2" string per capability, to send one per reply line (EHLO, CAPA,
	 *         FEAT)
	 */
	public List<String> toLines() {
		List<String> ret = new ArrayList<>(byName.size());
		for (Capability c : byName.values()) {
			ret.add(c.toString());
		}
		return ret;
	}

	/**
	 * @return all capabilities on one line separated by spaces, each parameter joined to its
	 *         name with '=' ("STARTTLS AUTH=PLAIN AUTH=LOGIN"), as IMAP lists them
	 */
	public String toInline() {
		StringBuilder buf = new StringBuilder();
		for (Capability c : byName.values()) {
			if (c.getParams().isEmpty()) {
				append(buf, c.getName());
			} else {
				for (String p : c.getParams()) {
					append(buf, c.getName() + "=" + p);
				}
			}
		}
		return buf.toString();
	}

	private static void append(StringBuilder buf, String s) {
		if (buf.length() > 0) {
			buf.append(' ');
		}
		buf.append(s);
	}

	/**
	 * Read capabilities listed one per line: the first word is the name, the rest are its
	 * parameters. Blank lines are skipped.
	 */
	public static CapabilitySet parseLines(Iterable<String> lines) {
		CapabilitySet ret = new CapabilitySet();
		for (String line : lines) {
			if (line == null) {
				continue;
			}
			String[] words = line.trim().split("\\s+");
			if (words[0].isEmpty()) {
				continue;
			}
			ret.add(words[0], java.util.Arrays.copyOfRange(words, 1, words.length));
		}
		return ret;
	}

	/**
	 * Read capabilities listed on one line (IMAP): words separated by spaces, where
	 * "NAME=param" is a parameter of NAME.
	 */
	public static CapabilitySet parseInline(String line) {
		CapabilitySet ret = new CapabilitySet();
		if (line == null) {
			return ret;
		}
		for (String word : line.trim().split("\\s+")) {
			if (word.isEmpty()) {
				continue;
			}
			int eq = word.indexOf('=');
			if (eq > 0) {
				ret.add(word.substring(0, eq), word.substring(eq + 1));
			} else {
				ret.add(word);
			}
		}
		return ret;
	}

	/**
	 * Read the capabilities from a multi-line reply ("250-host", "250-SIZE 1000", "250 8BITMIME").
	 * The "nnn-" or "nnn " prefix is removed from each line.
	 * <p>
	 * Use {@code skipFirst = 1} for EHLO (the first line greets) and
	 * {@code skipFirst = 1, skipLast = 1} for FTP FEAT ("211-Features:" ... "211 End").
	 *
	 * @param skipFirst lines to ignore at the start
	 * @param skipLast  lines to ignore at the end
	 */
	public static CapabilitySet parseReply(ICommandResponse reply, int skipFirst, int skipLast) {
		String[] full = reply.getFullResponse();
		List<String> lines = new ArrayList<>();
		if (full != null) {
			for (int idx = skipFirst; idx < full.length - skipLast; idx++) {
				lines.add(stripCode(full[idx]));
			}
		}
		return parseLines(lines);
	}

	private static String stripCode(String line) {
		if (line != null && line.length() >= 4 
				&& Character.isDigit(line.charAt(0)) && Character.isDigit(line.charAt(1)) 
				&& Character.isDigit(line.charAt(2))
				&& (line.charAt(3) == '-' || line.charAt(3) == ' ')) {
			return line.substring(4);
		}
		return line;
	}

	private static String key(String name) {
		return name.toUpperCase(Locale.ROOT);
	}

	@Override
	public String toString() {
		return toLines().toString();
	}
}
