package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.net.nio.NioServer;
import us.bringardner.parley.net.server.IBaseServer;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.Server;

/**
 * UserRegistry.close(): a server closes the registry it made from its provider setting when it
 * stops, and leaves a registry it was given alone.
 */
public class TestUserRegistryClose {

	private static final String NAME = "AclCloseServer";
	private static final String NIO_NAME = "AclCloseNioServer";

	/** A registry that counts its closes */
	public static class CountingRegistry implements UserRegistry {
		static final AtomicInteger made = new AtomicInteger();
		final AtomicInteger closed = new AtomicInteger();

		public CountingRegistry() {
			made.incrementAndGet();
		}

		@Override
		public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
			return false;
		}

		@Override
		public AuthenticationResult authenticate(Credential credential) {
			return AuthenticationResult.refused("nobody");
		}

		@Override
		public StoredCredential findStoredCredential(String user, StoredCredentialType type) {
			return null;
		}

		@Override
		public ParleyPrincipal findPrincipal(String name) {
			return null;
		}

		@Override
		public ParleyPrincipal findPrincipal(EntityId id) {
			return null;
		}

		@Override
		public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
			return AuthorizationResult.denied("nothing is granted");
		}

		@Override
		public void close() {
			closed.incrementAndGet();
		}
	}

	/** A registry made with the server it is for */
	public static class ServerRegistry extends CountingRegistry {
		final IBaseServer server;

		public ServerRegistry(IBaseServer server) {
			this.server = server;
		}
	}

	@AfterEach
	public void clearProperties() {
		System.clearProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY);
		System.clearProperty(NIO_NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY);
	}

	@Test
	public void theDefaultCloseDoesNothing() throws Exception {
		UserRegistry registry = ServerTestSupport.registry("alice, pw, Echo");
		registry.close();
		registry.close();
		assertNotNull(registry.findPrincipal("alice"), "a registry that holds nothing still answers");
	}

	/** The server gives itself to a registry that has a constructor for it. */
	@Test
	public void aRegistryIsMadeWithTheServer() throws Exception {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, ServerRegistry.class.getName());
		Server svr = new Server(0, NAME);
		ServerRegistry made = (ServerRegistry) svr.getUserRegistry();
		assertSame(svr, made.server);

		System.setProperty(NIO_NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, ServerRegistry.class.getName());
		NioServer nio = new NioServer(0, NIO_NAME);
		assertSame(nio, ((ServerRegistry) nio.getUserRegistry()).server);
	}

	@Test
	public void aClassThatIsNotARegistryIsRefused() {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, String.class.getName());
		final Server svr = new Server(0, NAME);
		svr.getLogger().setLevel(us.bringardner.parley.core.ILogger.Level.NONE);
		assertThrows(IllegalStateException.class, new Executable() {
			@Override
			public void execute() {
				svr.getUserRegistry();
			}
		});
	}

	@Test
	public void aServerClosesTheListItMadeWhenItStops() throws Exception {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingRegistry.class.getName());
		ServerTestSupport.TestServer svr = ServerTestSupport.create(NAME, ServerTestSupport.standardCommands(), null);
		ServerTestSupport.start(svr);
		CountingRegistry first = (CountingRegistry) svr.getUserRegistry();
		assertNotNull(first);
		assertSame(first, svr.getUserRegistry(), "made once");
		ServerTestSupport.stop(svr);
		assertEquals(1, first.closed.get(), "closed when the server stopped");

		// a restart makes a new one, closed again at the next stop
		ServerTestSupport.start(svr);
		CountingRegistry second = (CountingRegistry) svr.getUserRegistry();
		assertNotSame(first, second);
		ServerTestSupport.stop(svr);
		assertEquals(1, first.closed.get());
		assertEquals(1, second.closed.get());
	}

	@Test
	public void aListGivenToAServerIsTheCallers() throws Exception {
		CountingRegistry given = new CountingRegistry();
		ServerTestSupport.TestServer svr = ServerTestSupport.create(NAME, ServerTestSupport.standardCommands(), null);
		svr.setUserRegistry(given);
		ServerTestSupport.start(svr);
		ServerTestSupport.stop(svr);
		assertEquals(0, given.closed.get(), "the server doesn't close a registry it was given");
		assertSame(given, svr.getUserRegistry(), "and keeps it for a restart");
		given.close();
	}

	@Test
	public void replacingTheListItMadeClosesIt() throws Exception {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingRegistry.class.getName());
		Server svr = new Server(0, NAME);
		CountingRegistry made = (CountingRegistry) svr.getUserRegistry();
		svr.setUserRegistry(made); // given back: still the server's
		assertEquals(0, made.closed.get());
		CountingRegistry given = new CountingRegistry();
		svr.setUserRegistry(given);
		assertEquals(1, made.closed.get(), "the registry the server made is closed when replaced");
		svr.setUserRegistry(null);
		assertEquals(0, given.closed.get(), "a registry it was given isn't");
		given.close();
	}

	@Test
	public void aNioServerClosesTheListItMadeWhenItStops() throws Exception {
		System.setProperty(NIO_NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingRegistry.class.getName());
		NioServer server = new NioServer(0, NIO_NAME);
		server.setHandlerFactory(() -> (connection, frame) -> {
		});
		server.startAndWait(5000);
		CountingRegistry made = (CountingRegistry) server.getUserRegistry();
		assertNotNull(made);
		server.stop(5000, false);
		ServerTestSupport.waitFor(() -> !server.isRunning(), 5000, "server did not stop");
		assertEquals(1, made.closed.get(), "closed when the server stopped");

		CountingRegistry given = new CountingRegistry();
		server.setUserRegistry(given);
		server.startAndWait(5000);
		server.stop(5000, false);
		ServerTestSupport.waitFor(() -> !server.isRunning(), 5000, "server did not stop");
		assertEquals(0, given.closed.get(), "the server doesn't close a registry it was given");
		given.close();
	}
}
