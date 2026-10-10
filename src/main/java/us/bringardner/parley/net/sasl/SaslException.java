package us.bringardner.parley.net.sasl;

import java.io.IOException;

/** A SASL exchange failed on this side: bad data from the peer, or a peer that failed verification. */
public class SaslException extends IOException {

	private static final long serialVersionUID = 1L;

	public SaslException(String message) {
		super(message);
	}
}
