package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Authorizer;
import us.bringardner.parley.iam.BasicParleyPermission;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.Server;

/**
 * With no user registry configured, the setting is looked at once, not on every command.
 * Each check used to take the server's lock, look the setting up and log
 * "No user registry defined".
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
public class TestUserRegistryLookup {

	private static final class CountingServer extends Server {
		final AtomicInteger lookups = new AtomicInteger();

		CountingServer() {
			super(0, "AclLookup");
		}

		@Override
		public String getProperty(String name, String defaultValue) {
			if (propertyName(IServer.AUTHENTICATION_PROVIDER_PROPERTY).equals(name)) {
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
		ParleyPermission read = new BasicParleyPermission("read", null);
		for (int i = 0; i < 1000; i++) {
			assertThrows(IllegalStateException.class, () -> svr.checkPermission(ServerTestSupport.requester(), read, null));
		}
		assertNull(svr.getUserRegistry());
		assertNull(svr.getAuthorizer());
		assertThrows(IllegalStateException.class, () -> ServerTestSupport.login(svr, "u", "pw"));
		assertEquals(1, svr.lookups.get(), "provider property lookups");

		// setting a registry is used at once, with a default authorizer for it
		UserRegistry registry = ServerTestSupport.registry("u, pw, read");
		svr.setUserRegistry(registry);
		assertSame(registry, svr.getUserRegistry());
		assertNotNull(svr.getAuthorizer());
		assertSame(svr.getAuthorizer(), svr.getAuthorizer(), "made once for a registry");

		// clearing it looks at the property again, once
		svr.setUserRegistry(null);
		for (int i = 0; i < 10; i++) {
			assertNull(svr.getUserRegistry());
		}
		assertEquals(2, svr.lookups.get(), "provider property lookups after clearing");
	}

	/** An authorizer that is set is used instead of the default, with or without a registry. */
	@Test
	public void aGivenAuthorizerIsUsed() {
		Server svr = new Server(0, "GivenAuthorizer-" + System.nanoTime());
		Authorizer everything = new Authorizer() {
			@Override
			public AuthorizationResult check(Requester requester, ParleyPermission needed, ProtectedResource resource) {
				return AuthorizationResult.allowed("everything");
			}
		};
		svr.setAuthorizer(everything);
		assertSame(everything, svr.getAuthorizer());
		assertTrue(svr.checkPermission(ServerTestSupport.requester(), new BasicParleyPermission("x", null), null).isAllowed());
		svr.setAuthorizer(null);
		assertNull(svr.getAuthorizer(), "no registry, no default");
		assertThrows(IllegalStateException.class,
				() -> svr.checkPermission(ServerTestSupport.requester(), new BasicParleyPermission("x", null), null));
	}
}
