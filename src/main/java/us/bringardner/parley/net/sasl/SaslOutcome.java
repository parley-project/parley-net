package us.bringardner.parley.net.sasl;

/** How an authentication exchange ended, from {@link SaslServerDriver}. */
public final class SaslOutcome {

	public enum Status {
		/** The client proved its identity; {@link #getUser()} says who. */
		SUCCESS,
		/** The credentials were wrong, or the mechanism gave up. */
		FAILED,
		/** The client cancelled with "*". */
		CANCELLED,
		/** A response was not valid Base64. */
		MALFORMED,
		/** The connection closed in the middle of the exchange. */
		CLOSED
	}

	private final Status status;
	private final String user;
	private final String reason;

	SaslOutcome(Status status, String user, String reason) {
		this.status = status;
		this.user = user;
		this.reason = reason;
	}

	public Status getStatus() {
		return status;
	}

	public boolean isSuccess() {
		return status == Status.SUCCESS;
	}

	/** @return the authenticated user, for SUCCESS */
	public String getUser() {
		return user;
	}

	/** @return why it ended, for logs; null for SUCCESS */
	public String getReason() {
		return reason;
	}

	@Override
	public String toString() {
		return status + (user != null ? " " + user : "") + (reason != null ? " (" + reason + ")" : "");
	}
}
