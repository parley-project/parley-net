package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * LOGIN, the pre-standard mechanism some mail clients (Outlook) still need: the server asks
 * "Username:" then "Password:". Sends the password in the clear, so offer it only over TLS.
 * A user name sent with the command is accepted.
 */
public final class LoginMechanism implements ISaslMechanism {

	public static final String NAME = "LOGIN";

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
			private String user;

			@Override
			public SaslStep start(byte[] initialResponse) {
				if (initialResponse == null) {
					return SaslStep.challenge("Username:");
				}
				return respond(initialResponse);
			}

			@Override
			public SaslStep respond(byte[] response) {
				String text = new String(response, StandardCharsets.UTF_8);
				if (user == null) {
					if (text.isEmpty()) {
						return SaslStep.failure("No user name");
					}
					user = text;
					return SaslStep.challenge("Password:");
				}
				if (authenticator.checkPassword(user, text)) {
					return SaslStep.success(user);
				}
				return SaslStep.failure("Bad credentials");
			}
		};
	}

	/** @return the client side: answers the first challenge with the user, the second with the password */
	public static ISaslClient client(final String user, final String password) {
		return new ISaslClient() {
			private int answered;

			@Override
			public String getName() {
				return NAME;
			}

			@Override
			public boolean hasInitialResponse() {
				return false;
			}

			@Override
			public byte[] initialResponse() {
				return null;
			}

			@Override
			public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
				if (answered >= 2) {
					throw new SaslException("LOGIN: unexpected challenge");
				}
				String ret = answered++ == 0 ? user : password;
				return ret.getBytes(StandardCharsets.UTF_8);
			}

			@Override
			public boolean isComplete() {
				return answered == 2;
			}
		};
	}
}
