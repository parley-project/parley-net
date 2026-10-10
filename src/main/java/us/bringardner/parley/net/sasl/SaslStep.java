package us.bringardner.parley.net.sasl;

import java.nio.charset.StandardCharsets;

/**
 * What the server side of a SASL exchange does next: send a challenge, finish with success
 * (the user is known), or finish with failure.
 */
public final class SaslStep {

	public enum Kind {
		CHALLENGE, SUCCESS, FAILURE
	}

	private static final byte[] EMPTY = new byte[0];

	private final Kind kind;
	private final byte[] data;
	private final String text;

	private SaslStep(Kind kind, byte[] data, String text) {
		this.kind = kind;
		this.data = data;
		this.text = text;
	}

	/** Send this data to the client and wait for its response. */
	public static SaslStep challenge(byte[] data) {
		return new SaslStep(Kind.CHALLENGE, data.clone(), null);
	}

	public static SaslStep challenge(String data) {
		return new SaslStep(Kind.CHALLENGE, data.getBytes(StandardCharsets.UTF_8), null);
	}

	/** An empty challenge, asking the client for its first message. */
	public static SaslStep emptyChallenge() {
		return new SaslStep(Kind.CHALLENGE, EMPTY, null);
	}

	/** The client proved who it is. */
	public static SaslStep success(String user) {
		return new SaslStep(Kind.SUCCESS, EMPTY, user);
	}

	/** The exchange failed; the reason is for logs, not for the client. */
	public static SaslStep failure(String reason) {
		return new SaslStep(Kind.FAILURE, EMPTY, reason);
	}

	public Kind getKind() {
		return kind;
	}

	/** @return the challenge data (empty unless this is a CHALLENGE) */
	public byte[] getData() {
		return data.clone();
	}

	/** @return the authenticated user name, for SUCCESS */
	public String getUser() {
		return kind == Kind.SUCCESS ? text : null;
	}

	/** @return why the exchange failed, for FAILURE */
	public String getReason() {
		return kind == Kind.FAILURE ? text : null;
	}
}
