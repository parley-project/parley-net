package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.IBaseServer;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.net.server.Server;

/**
 * Shared helpers for tests that need a running server, TLS material or to wait for something.
 * Not a test itself.
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
public class ServerTestSupport {

	/** Self-signed certificate for CN=localhost (SAN dns:localhost only), valid until 2126. */
	public static final String KEYSTORE = "/test-keystore.p12";
	public static final String KEY_ALIAS = "test";
	public static final char[] PASSWORD = "changeit".toCharArray();
	/** {@link #PASSWORD} as text, for a server's keyStorePassword property. */
	public static final String KEYSTORE_PASSWORD = new String(PASSWORD);

	public static final String ECHO = "Echo";
	public static final String FAIL = "Fail";
	public static final String SECRET = "Secret";
	public static final String LOGIN = "Login";
	public static final String START_TLS = "StartTls";
	public static final String FAIL_DETAIL = "internal detail that must not reach the client";

	/**
	 * A Server that lets tests run the idle connection check on demand.
	 */
	public static class TestServer extends Server {
		public TestServer(String name) {
			super(0, name);
		}

		public void runAdmin() {
			doAdmin();
		}
	}

	public interface CommandBody {
		void execute(ICommandProcessor processor, IRequestContext context) throws IOException;
	}

	public static ICommand command(String name, boolean requiresAuthorization, CommandBody body) {
		return new ICommand() {
			@Override
			public String getName() {
				return name;
			}

			@Override
			public ParleyPermission getPermission() {
				return new BasicParleyPermission(name, null);
			}

			@Override
			public boolean requiresAuthorization() {
				return requiresAuthorization;
			}

			@Override
			public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
				body.execute(processor, context);
			}
		};
	}

	/**
	 * Echo (no auth), Fail (throws), Secret (needs the Secret permission), Login user password, StartTls.
	 */
	public static Map<String, ICommand> standardCommands() {
		Map<String, ICommand> ret = new HashMap<>();
		ret.put(ECHO, command(ECHO, false, (p, c) -> p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, c.getRemainingTokens())));
		ret.put(FAIL, command(FAIL, false, (p, c) -> {
			throw new IllegalStateException(FAIL_DETAIL);
		}));
		ret.put(SECRET, command(SECRET, true, (p, c) -> p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, "the secret")));
		ret.put(LOGIN, command(LOGIN, false, (p, c) -> {
			String user = c.getNextToken();
			String password = c.getNextToken();
			if( user == null || password == null ) {
				p.reply(IGenericResponseCode.REPLY_500_GENERIC_ERROR, "Not enough parameters");
				return;
			}
			AuthenticationResult result = p.authenticate(new PasswordCredential(user, password.toCharArray(), p.getRequester()));
			if( result.getStatus() != AuthenticationResult.Status.AUTHENTICATED ) {
				p.reply(IGenericResponseCode.REPLY_400_GENERIC_TEMPORARY_ERROR, "User not identified");
			} else {
				p.reply(IGenericResponseCode.REPLY_200_GENERIC_OK, "Ok");
			}
		}));
		ret.put(START_TLS, command(START_TLS, false, (p, c) -> {
			p.reply(220, "Ready to start TLS");
			p.getConnection().negotiateSecureSocket("TLS");
		}));
		return ret;
	}

	/**
	 * Create (not start) a server on a free port.
	 * @param tls server side TLS context for StartTls, or null
	 */
	public static TestServer create(String name, Map<String, ICommand> commands, SSLContext tls) {
		TestServer svr = new TestServer(name);
		// Short accept timeout so stop() is quick
		svr.setAcceptTimeout(200);
		svr.setConnectionFactory(socket -> new Connection(socket, true) {
			@Override
			public SSLContext getSSLContext(String sslOrTsl) throws IOException {
				if( tls == null ) {
					throw new IOException("TLS is not configured for this test server");
				}
				return tls;
			}
		});
		svr.setProcessorFactory(() -> new AbstractCommandProcessor() {
			private static final long serialVersionUID = 1L;

			@Override
			public String translateResponseCode(int code) {
				return "" + code;
			}

			@Override
			public ICommandFactory getCommandFactory() {
				return context -> {
					String name1 = context.getNextToken();
					return name1 == null ? null : commands.get(name1);
				};
			}
		});
		return svr;
	}

	public static TestServer start(TestServer svr) {
		svr.start();
		waitFor(svr::isRunning, 5000, "server did not start");
		return svr;
	}

	public static void stop(Server svr) {
		if( svr != null ) {
			svr.stop();
			waitFor(() -> !svr.isRunning(), 5000, "server did not stop");
		}
	}

	/**
	 * A user registry built from user file lines, e.g. "alice, pw, Echo|Secret".
	 */
	public static FileUserRegistry registry(String... lines) {
		return new FileUserRegistry() {
			{
				load(java.util.Arrays.asList(lines));
			}
		};
	}

	/** A requester for tests: no address, nobody logged in. */
	public static Requester requester() {
		return Requester.connected(null, 0, false, Requester.Transport.TCP, "test");
	}

	/** A password login through the server's door. */
	public static AuthenticationResult login(IBaseServer server, String user, String password) {
		return server.authenticate(new PasswordCredential(user, password.toCharArray(), requester()));
	}

	/** A password login straight to the registry. */
	public static AuthenticationResult login(UserRegistry registry, String user, String password) {
		return registry.authenticate(new PasswordCredential(user, password.toCharArray(), requester()));
	}

	/** @return the names of the permissions, in order */
	public static java.util.List<String> names(java.util.Collection<ParleyPermission> permissions) {
		java.util.List<String> ret = new java.util.ArrayList<String>();
		for (ParleyPermission permission : permissions) {
			ret.add(permission.getName());
		}
		return ret;
	}

	public static CommandClient connect(Server svr) throws IOException {
		return connect(svr, "localhost");
	}

	public static CommandClient connect(Server svr, String host) throws IOException {
		CommandClient client = newClient(svr, host);
		assertTrue(client.connect(), "connect failed: " + client.getLastConnectError());
		return client;
	}

	public static CommandClient newClient(Server svr, String host) {
		CommandClient client = new CommandClient(host, svr.getLocalPort());
		// Fail fast instead of hanging a test run
		client.setTimeout(5000);
		return client;
	}

	public static void waitFor(BooleanSupplier condition, long timeoutMs, String message) {
		long end = System.currentTimeMillis() + timeoutMs;
		while( !condition.getAsBoolean()) {
			if( System.currentTimeMillis() > end ) {
				throw new AssertionError(message);
			}
			try {
				Thread.sleep(20);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new AssertionError(message, e);
			}
		}
	}

	// ---------- TLS material

	/**
	 * Write the test keystore ({@link #KEYSTORE}: PKCS12, alias {@link #KEY_ALIAS}, password
	 * {@link #KEYSTORE_PASSWORD}) to a file, for a server configured with its keyStoreName,
	 * keyStorePassword and keyStoreType (PKCS12) properties. The file is replaced in one step, so
	 * tests running at once never see it half written.
	 */
	public static synchronized void writeKeystore(FileSource file) throws IOException {
		FileSource dir = file.getParentFile();
		if( dir != null && !dir.isDirectory() ) {
			dir.mkdirs();
		}
		FileSource tmp = dir.getFileSourceFactory().createTempFile("keystore", ".tmp", dir);
		boolean moved = false;
		try {
			try (InputStream in = ServerTestSupport.class.getResourceAsStream(KEYSTORE)) {
				if( in == null ) {
					throw new IllegalStateException("Missing test resource " + KEYSTORE);
				}
				try (java.io.OutputStream out = tmp.getOutputStream()) {
					in.transferTo(out);
				}
			}
			// one step where the file system's getCapabilities().atomicReplace() says so (local files)
			moved = tmp.renameTo(file, true);
			if( !moved ) {
				throw new IOException("Can't replace " + file + " with " + tmp);
			}
		} finally {
			if( !moved && tmp.exists() ) {
				tmp.delete();
			}
		}
	}

	public static KeyStore keyStore() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (InputStream in = ServerTestSupport.class.getResourceAsStream(KEYSTORE)) {
			if( in == null ) {
				throw new IllegalStateException("Missing test resource " + KEYSTORE);
			}
			ks.load(in, PASSWORD);
		}
		return ks;
	}

	public static X509Certificate certificate() throws Exception {
		return (X509Certificate) keyStore().getCertificate(KEY_ALIAS);
	}

	/** Server side TLS context using the test key. */
	public static SSLContext serverContext() throws Exception {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore(), PASSWORD);
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(kmf.getKeyManagers(), null, null);
		return ctx;
	}

	/** Trust managers that trust the test certificate as if it were CA signed. */
	public static TrustManager[] trustingTestCertificate() throws Exception {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore());
		return tmf.getTrustManagers();
	}

	private static FileSource testHome;

	/**
	 * DynamicTrustManager saves approvals in ${user.home}/.parley/trusted-certificates.
	 * Point user.home at a temporary directory so tests never touch the real file. The directory
	 * is new for each test run (so approvals saved by an earlier run can't leak in), shared by all
	 * the tests in this run, and left in place afterwards so it can be inspected; the OS clears its
	 * temp directory in time.
	 * @return the test home directory
	 */
	public static synchronized FileSource useTestHome() {
		if( testHome == null ) {
			try {
				// local: DynamicTrustManager finds user.home on the default file system
				testHome = FileSourceFactory.fileProxyFactory.createTempDirectory("parley-net-test-home");
			} catch(IOException e) {
				throw new UncheckedIOException(e);
			}
			System.out.println("parley-net test home: "+testHome);
		}
		System.setProperty("user.home", testHome.getPath());
		return testHome;
	}
}
