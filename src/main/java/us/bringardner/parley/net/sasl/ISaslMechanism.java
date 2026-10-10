package us.bringardner.parley.net.sasl;

/**
 * A SASL mechanism (RFC 4422): PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-256, XOAUTH2 ...
 * Implementations are stateless and shared; each exchange gets its own {@link ISaslServer}.
 * Client sides are created by factory methods on the mechanism classes, since each needs
 * different credentials.
 */
public interface ISaslMechanism {

	/** @return the registered mechanism name, upper case */
	String getName();

	/**
	 * @return true if a passive eavesdropper can read the secret from the exchange. Such a
	 *         mechanism should be offered only over TLS.
	 */
	boolean isPlaintext();

	/**
	 * @param authenticator checks the credentials
	 * @return a new server side of the exchange
	 */
	ISaslServer newServer(ISaslAuthenticator authenticator);
}
