package us.bringardner.parley.net.sasl;

/**
 * Where a server's SASL mechanisms check credentials. A mechanism calls only the method it
 * needs, and {@link #supports(String)} says which mechanisms this store can serve: a store of
 * salted password hashes can check a PLAIN password but can't answer CRAM-MD5, which needs
 * the password itself.
 * <p>
 * Instances are used by one session at a time.
 */
public interface ISaslAuthenticator {

	/** @return true if the user's password is correct (PLAIN, LOGIN) */
	boolean checkPassword(String user, String password);

	/** @return the user's clear text password, or null if unknown or not available (CRAM-MD5) */
	default String getPassword(String user) {
		return null;
	}

	/**
	 * @param hash "SHA-1" or "SHA-256"
	 * @return the user's stored SCRAM credentials for that hash, or null if there are none
	 */
	default ScramCredentials getScramCredentials(String user, String hash) {
		return null;
	}

	/** @return true if the bearer token is valid for the user (XOAUTH2) */
	default boolean checkBearerToken(String user, String token) {
		return false;
	}

	/** @return true if this store can serve the mechanism; the default says it can serve all */
	default boolean supports(String mechanism) {
		return true;
	}
}
