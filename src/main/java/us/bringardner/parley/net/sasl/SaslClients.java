package us.bringardner.parley.net.sasl;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Makes the client side of the password mechanisms by name, and picks one from what a server
 * offers, so a mail or other client doesn't repeat that choice.
 * <pre>
 *   ISaslClient sasl = SaslClients.choose(offeredNames, Arrays.asList("SCRAM-SHA-256", "PLAIN"), user, password);
 *   if (sasl != null) { ... run AUTH with sasl ... }
 * </pre>
 * XOAUTH2 isn't here because it takes a token, not a password: use
 * {@link XOAuth2Mechanism#client(String, String)}.
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
public final class SaslClients {

	/** The password mechanisms, strongest first. */
	public static final List<String> STRONGEST_FIRST = Arrays.asList(
			"SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5", "PLAIN", "LOGIN");

	private SaslClients() {
	}

	/** @return true if {@link #create} can make a client for the mechanism (any case) */
	public static boolean isSupported(String mechanism) {
		return mechanism != null && STRONGEST_FIRST.contains(mechanism.toUpperCase(Locale.ROOT));
	}

	/**
	 * @param mechanism one of {@link #STRONGEST_FIRST}, in any case
	 * @return a new client for one exchange, or null if the mechanism is not one of those
	 */
	public static ISaslClient create(String mechanism, String user, String password) {
		if (mechanism == null) {
			return null;
		}
		switch (mechanism.toUpperCase(Locale.ROOT)) {
		case "SCRAM-SHA-256":
			return ScramMechanism.SHA_256.client(user, password);
		case "SCRAM-SHA-1":
			return ScramMechanism.SHA_1.client(user, password);
		case "CRAM-MD5":
			return CramMd5Mechanism.client(user, password);
		case "PLAIN":
			return PlainMechanism.client(user, password);
		case "LOGIN":
			return LoginMechanism.client(user, password);
		default:
			return null;
		}
	}

	/**
	 * The first mechanism in the preference list that the server offers and that this class can
	 * make. The preference list decides, not the server's order, so a client can refuse the
	 * mechanisms it doesn't want (for instance anything but SCRAM).
	 *
	 * @param offered   the server's mechanism names, in any case
	 * @param preferred the mechanisms the caller will use, best first
	 * @return a new client, or null if there is no match
	 */
	public static ISaslClient choose(Collection<String> offered, List<String> preferred, String user,
			String password) {
		for (String want : preferred) {
			for (String have : offered) {
				if (want.equalsIgnoreCase(have)) {
					ISaslClient ret = create(want, user, password);
					if (ret != null) {
						return ret;
					}
				}
			}
		}
		return null;
	}
}
