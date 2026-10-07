package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.server.FileBasedAcl.FileBasedPrincipal;
import us.bringardner.parley.net.server.IAccessControlList;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.Permission;
import us.bringardner.parley.net.server.Server;

/**
 * With no access control provider configured, the property is looked at once, not on every
 * command (BJL-42). Each check used to take the server's lock, look the property up and log
 * "No access control defined".
 */
public class TestAccessControlLookup {

	private static final class CountingServer extends Server {
		final AtomicInteger lookups = new AtomicInteger();

		CountingServer() {
			super(0, "AclLookup");
		}

		@Override
		public String getProperty(String name, String defaultValue) {
			if (IServer.AUTHENTICATION_PROVIDER_PROPERTY.equals(name)) {
				lookups.incrementAndGet();
			}
			return super.getProperty(name, defaultValue);
		}
	}

	@Test
	public void noProviderIsLookedUpOnce() {
		System.clearProperty(IServer.AUTHENTICATION_PROVIDER_PROPERTY);
		System.clearProperty("AclLookup." + IServer.AUTHENTICATION_PROVIDER_PROPERTY);
		CountingServer svr = new CountingServer();
		IPermission read = new Permission("read");
		for (int i = 0; i < 1000; i++) {
			assertFalse(svr.isAuthorized(new FileBasedPrincipal("u"), read));
		}
		assertNull(svr.getAccessControl());
		assertEquals(1, svr.lookups.get(), "provider property lookups");

		// setting an ACL is used at once
		IAccessControlList acl = ServerTestSupport.acl("u, pw, read");
		svr.setAccessControl(acl);
		assertSame(acl, svr.getAccessControl());

		// clearing it looks at the property again, once
		svr.setAccessControl(null);
		for (int i = 0; i < 10; i++) {
			assertNull(svr.getAccessControl());
		}
		assertEquals(2, svr.lookups.get(), "provider property lookups after clearing");
	}
}
