package us.bringardner.parley.net.sasl;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The mechanisms a server knows, in the order it prefers them. Protocol code asks
 * {@link #offered} for the names to advertise (the AUTH line of EHLO, SASL in CAPA,
 * AUTH= in CAPABILITY) and {@link #find} for the mechanism the client picked.
 */
public class SaslMechanisms {

	private final Map<String, ISaslMechanism> byName = new LinkedHashMap<>();

	/**
	 * @param host the host name for CRAM-MD5 challenges
	 * @return SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5, PLAIN, LOGIN and XOAUTH2, strongest first
	 */
	public static SaslMechanisms standard(String host) {
		SaslMechanisms ret = new SaslMechanisms();
		ret.register(ScramMechanism.SHA_256);
		ret.register(ScramMechanism.SHA_1);
		ret.register(new CramMd5Mechanism(host));
		ret.register(new PlainMechanism());
		ret.register(new LoginMechanism());
		ret.register(new XOAuth2Mechanism());
		return ret;
	}

	/** Add a mechanism, or replace the one of the same name (which keeps its place). */
	public SaslMechanisms register(ISaslMechanism mechanism) {
		byName.put(mechanism.getName().toUpperCase(Locale.ROOT), mechanism);
		return this;
	}

	public SaslMechanisms unregister(String name) {
		byName.remove(name.toUpperCase(Locale.ROOT));
		return this;
	}

	/** @return the mechanism of that name (any case), or null */
	public ISaslMechanism find(String name) {
		return name == null ? null : byName.get(name.toUpperCase(Locale.ROOT));
	}

	/**
	 * @param authenticator the credential store, which says what it can serve
	 * @param secure        true if the connection uses TLS; plaintext mechanisms are offered
	 *                      only then
	 * @return the names to advertise, in preference order
	 */
	public List<String> offered(ISaslAuthenticator authenticator, boolean secure) {
		List<String> ret = new ArrayList<>();
		for (ISaslMechanism m : byName.values()) {
			if (authenticator.supports(m.getName()) && (secure || !m.isPlaintext())) {
				ret.add(m.getName());
			}
		}
		return ret;
	}
}
