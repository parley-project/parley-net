package us.bringardner.parley.net.sasl;

import java.io.IOException;

import us.bringardner.parley.net.sasl.SaslOutcome.Status;

/**
 * Runs the server side of an authentication exchange over a connection, so that the AUTH
 * command of each protocol only supplies the lines it uses to carry the data:
 * <pre>
 *   SaslOutcome out = SaslServerDriver.authenticate(mech, authenticator, initialResponseOrNull,
 *       new ISaslChannel() {
 *           public void sendChallenge(String b64) throws IOException { processor.reply("334 " + b64); }
 *           public String readResponse() throws IOException { return processor.readLine(); }
 *       });
 *   if (out.isSuccess()) { ... reply 235 ... } else { ... reply 535 ... }
 * </pre>
 * The driver handles the parts every protocol shares: "=" for an empty response, "*" to
 * cancel, invalid Base64, and a bound on the number of rounds.
 */
public final class SaslServerDriver {

	/** More challenges than any mechanism here needs; stops a mechanism that never finishes. */
	public static final int MAX_ROUNDS = 8;

	private SaslServerDriver() {
	}

	/**
	 * @param initialResponse the Base64 text that followed the command, or null if none
	 * @throws IOException if the channel fails
	 */
	public static SaslOutcome authenticate(ISaslMechanism mechanism, ISaslAuthenticator authenticator,
			String initialResponse, ISaslChannel channel) throws IOException {
		byte[] first = null;
		if (initialResponse != null) {
			try {
				first = SaslEncoding.decode(initialResponse);
			} catch (IllegalArgumentException e) {
				return new SaslOutcome(Status.MALFORMED, null, "Invalid Base64 in the initial response");
			}
		}
		ISaslServer server = mechanism.newServer(authenticator);
		SaslStep step = server.start(first);
		for (int round = 0;; round++) {
			switch (step.getKind()) {
			case SUCCESS:
				return new SaslOutcome(Status.SUCCESS, step.getUser(), null);
			case FAILURE:
				return new SaslOutcome(Status.FAILED, null, step.getReason());
			default:
				break;
			}
			if (round >= MAX_ROUNDS) {
				return new SaslOutcome(Status.FAILED, null, "Too many rounds");
			}
			channel.sendChallenge(SaslEncoding.encode(step.getData()));
			String line = channel.readResponse();
			if (line == null) {
				return new SaslOutcome(Status.CLOSED, null, "Connection closed");
			}
			line = line.trim();
			if (line.equals("*")) {
				return new SaslOutcome(Status.CANCELLED, null, "Cancelled by the client");
			}
			byte[] response;
			try {
				response = SaslEncoding.decode(line);
			} catch (IllegalArgumentException e) {
				return new SaslOutcome(Status.MALFORMED, null, "Invalid Base64 in a response");
			}
			step = server.respond(response);
		}
	}
}
