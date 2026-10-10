package us.bringardner.parley.net.capability;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * One thing a peer says it supports: a name and optional parameters. This is what the
 * protocols list in SMTP's EHLO ("SIZE 35882577", "AUTH PLAIN LOGIN"), POP3's CAPA
 * ("SASL PLAIN"), FTP's FEAT ("MLST size*;type*") and IMAP's CAPABILITY ("AUTH=PLAIN").
 * <p>
 * Names are matched without regard to case; the case the peer used is kept for display.
 * Instances are immutable.
 */
public final class Capability {

	private final String name;
	private final List<String> params;

	public Capability(String name, List<String> params) {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("A capability needs a name");
		}
		this.name = name;
		this.params = Collections.unmodifiableList(new ArrayList<>(params));
	}

	public Capability(String name, String... params) {
		this(name, java.util.Arrays.asList(params));
	}

	/** @return the name as it was given */
	public String getName() {
		return name;
	}

	/** @return the parameters in order, possibly empty */
	public List<String> getParams() {
		return params;
	}

	/** @return true if the name matches, ignoring case */
	public boolean isNamed(String other) {
		return name.equalsIgnoreCase(other);
	}

	/** @return true if this has the parameter, ignoring case */
	public boolean hasParam(String param) {
		for (String p : params) {
			if (p.equalsIgnoreCase(param)) {
				return true;
			}
		}
		return false;
	}

	/** @return "NAME p1 p2", the way line based protocols list it */
	@Override
	public String toString() {
		if (params.isEmpty()) {
			return name;
		}
		return name + " " + String.join(" ", params);
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof Capability)) {
			return false;
		}
		Capability other = (Capability) o;
		return name.equalsIgnoreCase(other.name) && params.equals(other.params);
	}

	@Override
	public int hashCode() {
		return name.toUpperCase(Locale.ROOT).hashCode() * 31 + params.hashCode();
	}
}
