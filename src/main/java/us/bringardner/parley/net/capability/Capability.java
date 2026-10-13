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
