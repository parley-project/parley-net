package us.bringardner.parley.net.sasl;

import java.io.IOException;

/**
 * How a protocol carries SASL data: the part {@link SaslServerDriver} can't know. SMTP sends
 * "334 &lt;base64&gt;", IMAP and POP3 send "+ &lt;base64&gt;"; all of them read the answer as a line.
 */
public interface ISaslChannel {

	/**
	 * Send a challenge, as the protocol's continuation reply.
	 *
	 * @param base64 the challenge, Base64 encoded ("" if empty)
	 */
	void sendChallenge(String base64) throws IOException;

	/**
	 * @return the client's response line, or null if the connection was closed
	 */
	String readResponse() throws IOException;
}
