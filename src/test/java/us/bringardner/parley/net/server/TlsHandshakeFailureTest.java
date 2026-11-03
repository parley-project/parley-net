package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;

/** Which failures are a client's failed TLS handshake, logged as one line instead of an error. */
public class TlsHandshakeFailureTest {

	@Test
	public void aHandshakeFailureOrOneItCausedIsTheClients() {
		SSLHandshakeException hungUp = new SSLHandshakeException("Remote host terminated the handshake");
		hungUp.initCause(new EOFException("SSL peer shut down incorrectly"));
		assertTrue(AbstractCommandProcessor.isTlsHandshakeFailure(hungUp));
		assertTrue(AbstractCommandProcessor.isTlsHandshakeFailure(new SSLHandshakeException("(handshake_failure) no cipher suites in common")));
		assertTrue(AbstractCommandProcessor.isTlsHandshakeFailure(new IOException("STLS", hungUp)));
	}

	@Test
	public void otherFailuresAreNot() {
		assertFalse(AbstractCommandProcessor.isTlsHandshakeFailure(null));
		assertFalse(AbstractCommandProcessor.isTlsHandshakeFailure(new IOException("disk full")));
		assertFalse(AbstractCommandProcessor.isTlsHandshakeFailure(new SocketException("Connection reset")));
		assertFalse(AbstractCommandProcessor.isTlsHandshakeFailure(new SSLException("Tag mismatch")), "after the handshake");
		Throwable loop = new IOException("a");
		loop.initCause(new RuntimeException("b", null));
		assertFalse(AbstractCommandProcessor.isTlsHandshakeFailure(loop));
	}
}
