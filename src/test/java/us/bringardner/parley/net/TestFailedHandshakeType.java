package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.ICommand;

/**
 * A client that offers no signature algorithm the server's RSA key can use fails the handshake with
 * a plain SSLException from the JDK ("No supported signature algorithm for RSA key"). The server's
 * negotiateSecureSocket must report it as the failed handshake it is, so servers log it as the
 * client's doing and not as an error of their own.
 *
 * <PRE>
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 */
public class TestFailedHandshakeType {

	private static TestServer svr;

	@BeforeAll
	public static void createServer() throws Exception {
		Map<String, ICommand> commands = ServerTestSupport.standardCommands();
		svr = ServerTestSupport.create("HandshakeTypeServer", commands, null);
		svr.setKeyStoreType("PKCS12");
		svr.setKeyStoreFileName(ServerTestSupport.KEYSTORE);
		svr.setKeyStorePassword(new String(ServerTestSupport.PASSWORD));
		svr.setProtocol("TLS");
	}

	@AfterAll
	public static void closeServer() {
		ServerTestSupport.stop(svr);
	}

	/** SSLParameters.setSignatureSchemes is Java 19+; the tests that need it are skipped before that. */
	private static void setSignatureSchemes(SSLParameters p, String... schemes) {
		try {
			SSLParameters.class.getMethod("setSignatureSchemes", String[].class).invoke(p, (Object) schemes);
		} catch (ReflectiveOperationException e) {
			assumeTrue(false, "needs Java 19 or later");
		}
	}

	@Test
	public void noUsableSignatureAlgorithmIsAFailedHandshake() throws Exception {
		IOException thrown = serverSideNegotiation(client -> {
			SSLParameters p = client.getSSLParameters();
			p.setProtocols(new String[] { "TLSv1.2" });
			p.setCipherSuites(new String[] { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" });
			// only ECDSA: nothing the server's RSA key can sign with
			setSignatureSchemes(p, "ecdsa_secp256r1_sha256");
			client.setSSLParameters(p);
		});
		assertNotNull(thrown, "the server's negotiation should have failed");
		assertTrue(thrown instanceof SSLHandshakeException, "type was " + thrown);
		assertTrue(AbstractCommandProcessor.isTlsHandshakeFailure(thrown));
		assertNotNull(thrown.getCause(), "the JDK's own exception is kept as the cause");
		assertTrue(thrown.getCause() instanceof SSLException);
		assertTrue(thrown.getMessage().contains("signature"), thrown.getMessage());
	}

	@Test
	public void aClientThatHangsUpIsAFailedHandshakeToo() throws Exception {
		IOException thrown = serverSideNegotiation(client -> {
			try {
				client.close();
			} catch (IOException e) {
				// closing is the point
			}
		});
		assertNotNull(thrown);
		assertTrue(AbstractCommandProcessor.isTlsHandshakeFailure(thrown), "type was " + thrown);
	}

	@Test
	public void aGoodClientStillNegotiates() throws Exception {
		assertNull(serverSideNegotiation(client -> {
		}, true));
	}

	private IOException serverSideNegotiation(ClientSetup setup) throws Exception {
		return serverSideNegotiation(setup, false);
	}

	/**
	 * Accepts one client, runs the server's side of negotiateSecureSocket on it, and returns what it
	 * threw (null if it worked); the client side is set up and then started.
	 */
	private IOException serverSideNegotiation(ClientSetup setup, boolean trustTestCertificate) throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			Future<IOException> server = pool.submit(() -> {
				try (Socket accepted = listener.accept()) {
					accepted.setSoTimeout(10000);
					Connection con = new Connection(accepted, true) {
						@Override
						public SSLContext getSSLContext(String sslOrTsl) throws IOException {
							return svr.getSSLContext(sslOrTsl);
						}
					};
					try {
						con.negotiateSecureSocket("TLS");
						return null;
					} catch (IOException e) {
						return e;
					}
				}
			});
			pool.submit(() -> {
				SSLContext ctx = SSLContext.getInstance("TLS");
				ctx.init(null, trustTestCertificate ? ServerTestSupport.trustingTestCertificate() : null, null);
				try (Socket plain = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
						SSLSocket tls = (SSLSocket) ctx.getSocketFactory().createSocket(plain, "localhost", plain.getPort(), true)) {
					tls.setSoTimeout(10000);
					setup.setup(tls);
					if (!tls.isClosed()) {
						tls.startHandshake();
					}
				} catch (IOException e) {
					// the handshake is expected to fail in most of these
				}
				return null;
			});
			return server.get(30, TimeUnit.SECONDS);
		} finally {
			pool.shutdownNow();
			assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "threads left running");
		}
	}

	private interface ClientSetup {
		void setup(SSLSocket client) throws IOException;
	}
}
