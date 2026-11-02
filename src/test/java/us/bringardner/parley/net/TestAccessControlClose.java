package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.nio.NioServer;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.Server;
import us.bringardner.parley.net.server.ServerContext;

/**
 * IAccessControlList.close() (To-Do 3.3): a server closes the list it made from its provider
 * setting when it stops, and leaves a list it was given alone.
 */
public class TestAccessControlClose {

	private static final String NAME = "AclCloseServer";
	private static final String NIO_NAME = "AclCloseNioServer";

	/** A list that counts its closes */
	public static class CountingAcl implements IAccessControlList {
		static final AtomicInteger made = new AtomicInteger();
		final AtomicInteger closed = new AtomicInteger();

		public CountingAcl() {
			made.incrementAndGet();
		}

		@Override
		public void initialize(IServer server) throws IOException {
		}

		@Override
		public void initialize(String serverName) throws IOException {
		}

		@Override
		public boolean checkPermission(IPrincipal user, IPermission action) {
			return false;
		}

		@Override
		public IPrincipal getPrincipal(String user) {
			return null;
		}

		@Override
		public boolean verifyPassword(IPrincipal user, byte[] credentials) {
			return false;
		}

		@Override
		public void close() {
			closed.incrementAndGet();
		}
	}

	@AfterEach
	public void clearProperties() {
		System.clearProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY);
		System.clearProperty(NIO_NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY);
	}

	@Test
	public void theDefaultCloseDoesNothing() throws Exception {
		IAccessControlList acl = ServerTestSupport.acl("alice, pw, Echo");
		acl.close();
		acl.close();
		assertNotNull(acl.getPrincipal("alice"), "a list that holds nothing still answers");
	}

	@Test
	public void aServerClosesTheListItMadeWhenItStops() throws Exception {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingAcl.class.getName());
		ServerTestSupport.TestServer svr = ServerTestSupport.create(NAME, ServerTestSupport.standardCommands(), null);
		ServerTestSupport.start(svr);
		CountingAcl first = (CountingAcl) svr.getAccessControl();
		assertNotNull(first);
		assertSame(first, svr.getAccessControl(), "made once");
		ServerTestSupport.stop(svr);
		assertEquals(1, first.closed.get(), "closed when the server stopped");

		// a restart makes a new one, closed again at the next stop
		ServerTestSupport.start(svr);
		CountingAcl second = (CountingAcl) svr.getAccessControl();
		assertNotSame(first, second);
		ServerTestSupport.stop(svr);
		assertEquals(1, first.closed.get());
		assertEquals(1, second.closed.get());
	}

	@Test
	public void aListGivenToAServerIsTheCallers() throws Exception {
		CountingAcl given = new CountingAcl();
		ServerTestSupport.TestServer svr = ServerTestSupport.create(NAME, ServerTestSupport.standardCommands(), null);
		svr.setAccessControl(given);
		ServerTestSupport.start(svr);
		ServerTestSupport.stop(svr);
		assertEquals(0, given.closed.get(), "the server doesn't close a list it was given");
		assertSame(given, svr.getAccessControl(), "and keeps it for a restart");
		given.close();
	}

	@Test
	public void replacingTheListItMadeClosesIt() throws Exception {
		System.setProperty(NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingAcl.class.getName());
		Server svr = new Server(0, NAME);
		CountingAcl made = (CountingAcl) svr.getAccessControl();
		svr.setAccessControl(made); // given back: still the server's
		assertEquals(0, made.closed.get());
		CountingAcl given = new CountingAcl();
		svr.setAccessControl(given);
		assertEquals(1, made.closed.get(), "the list the server made is closed when replaced");
		svr.setAccessControl(null);
		assertEquals(0, given.closed.get(), "a list it was given isn't");
		given.close();
	}

	@Test
	public void aNioServerClosesTheListItMadeWhenItStops() throws Exception {
		System.setProperty(NIO_NAME + "." + IServer.AUTHENTICATION_PROVIDER_PROPERTY, CountingAcl.class.getName());
		NioServer server = new NioServer(0, NIO_NAME);
		server.setHandlerFactory(() -> (connection, frame) -> {
		});
		server.startAndWait(5000);
		CountingAcl made = (CountingAcl) server.getAccessControl();
		assertNotNull(made);
		server.stop(5000, false);
		ServerTestSupport.waitFor(() -> !server.isRunning(), 5000, "server did not stop");
		assertEquals(1, made.closed.get(), "closed when the server stopped");

		CountingAcl given = new CountingAcl();
		server.setAccessControl(given);
		server.startAndWait(5000);
		server.stop(5000, false);
		ServerTestSupport.waitFor(() -> !server.isRunning(), 5000, "server did not stop");
		assertEquals(0, given.closed.get(), "the server doesn't close a list it was given");
		given.close();
	}

	@Test
	public void aSharedListIsClosedWithTheContext() throws Exception {
		ServerContext context = new ServerContext();
		CountingAcl shared = context.shared("users", CountingAcl.class, CountingAcl::new);
		assertSame(shared, context.shared("users", CountingAcl.class, CountingAcl::new));
		assertFalse(shared.closed.get() > 0);
		context.close();
		assertEquals(1, shared.closed.get(), "an IAccessControlList is AutoCloseable, so the context closes it");
		assertTrue(CountingAcl.made.get() > 0);
	}
}
