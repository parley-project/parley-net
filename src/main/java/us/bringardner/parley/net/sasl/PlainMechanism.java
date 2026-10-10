package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * PLAIN (RFC 4616): one message, "authzid NUL authcid NUL password". Sends the password in the
 * clear, so offer it only over TLS. An authorization identity that differs from the
 * authentication identity (acting as another user) is refused.
 */
public final class PlainMechanism implements ISaslMechanism {

	public static final String NAME = "PLAIN";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean isPlaintext() {
		return true;
	}

	@Override
	public ISaslServer newServer(ISaslAuthenticator authenticator) {
		return new ISaslServer() {
			@Override
			public SaslStep start(byte[] initialResponse) {
				return initialResponse == null ? SaslStep.emptyChallenge() : respond(initialResponse);
			}

			@Override
			public SaslStep respond(byte[] response) {
				String[] parts = new String(response, StandardCharsets.UTF_8).split("\u0000", -1);
				if (parts.length != 3 || parts[1].isEmpty()) {
					return SaslStep.failure("Malformed PLAIN response");
				}
				if (!parts[0].isEmpty() && !parts[0].equals(parts[1])) {
					return SaslStep.failure("Authorization identity differs from the user");
				}
				if (authenticator.checkPassword(parts[1], parts[2])) {
					return SaslStep.success(parts[1]);
				}
				return SaslStep.failure("Bad credentials");
			}
		};
	}

	/** @return the client side, which sends the credentials as the initial response */
	public static ISaslClient client(final String user, final String password) {
		return new ISaslClient() {
			private boolean sent;

			@Override
			public String getName() {
				return NAME;
			}

			@Override
			public boolean hasInitialResponse() {
				return true;
			}

			@Override
			public byte[] initialResponse() {
				sent = true;
				return ("\u0000" + user + "\u0000" + password).getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) {
				return initialResponse();
			}

			@Override
			public boolean isComplete() {
				return sent;
			}
		};
	}
}
