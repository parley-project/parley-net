package us.bringardner.parley.net.sasl;

/**
 * The client side of one authentication exchange, protocol independent. The protocol code
 * sends "AUTH name [initial response]", then answers each challenge with
 * {@link #evaluateChallenge(byte[])} until the server reports success or failure.
 * <p>
 * Challenges and responses are raw bytes; {@link SaslEncoding} converts to and from the Base64
 * the protocols carry. One instance per exchange.
 */
public interface ISaslClient {

	String getName();

	/**
	 * @return true if the mechanism starts with a message from the client, which can be sent
	 *         with the command (when the server allows it) instead of waiting for an empty
	 *         challenge
	 */
	boolean hasInitialResponse();

	/**
	 * @return the first message, or null if the mechanism waits for the server. If the server
	 *         doesn't take initial responses, answer its empty first challenge with
	 *         {@code evaluateChallenge(new byte[0])}, which returns the same bytes.
	 */
	byte[] initialResponse() throws SaslException;

	/**
	 * @param challenge the server's data (empty if it sent none)
	 * @return the response to send (possibly empty)
	 * @throws SaslException if the challenge is invalid, or the server fails verification
	 */
	byte[] evaluateChallenge(byte[] challenge) throws SaslException;

	/**
	 * @return true once the client has nothing more to send and has verified what it can. The
	 *         server's own success reply still decides the outcome.
	 */
	boolean isComplete();
}
