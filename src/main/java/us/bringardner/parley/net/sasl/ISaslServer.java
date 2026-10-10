package us.bringardner.parley.net.sasl;

/**
 * The server side of one authentication exchange. It knows nothing about the protocol that
 * carries it (AUTH in SMTP, AUTHENTICATE in IMAP, ...): bytes in, a {@link SaslStep} out.
 * Use {@link SaslServerDriver} to run it over a connection. One instance per exchange.
 */
public interface ISaslServer {

	/**
	 * Begin the exchange.
	 *
	 * @param initialResponse what the client sent with the command, or null if it sent
	 *                        nothing. An empty array is an empty initial response.
	 */
	SaslStep start(byte[] initialResponse);

	/** The client answered a challenge. */
	SaslStep respond(byte[] response);
}
