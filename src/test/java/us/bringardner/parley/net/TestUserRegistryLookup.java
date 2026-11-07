package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.net.server.FileUserRegistry;
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
		assertThrows(IllegalStateException.class, () -> ServerTestSupport.login(svr, "u", "pw"));
		assertEquals(1, svr.lookups.get(), "provider property lookups");

		// setting a registry is used at once
		UserRegistry registry = ServerTestSupport.registry("u, pw, read");
		svr.setUserRegistry(registry);
		assertSame(registry, svr.getUserRegistry());

		// clearing it looks at the property again, once
		svr.setUserRegistry(null);
		for (int i = 0; i < 10; i++) {
			assertNull(svr.getUserRegistry());
		}
		assertEquals(2, svr.lookups.get(), "provider property lookups after clearing");
	}

	/** The registry answers the check (rule 5); the server only passes its answer on. */
	@Test
	public void theRegistryDecides() {
		Server svr = new Server(0, "RegistryDecides-" + System.nanoTime());
		ParleyPermission x = new BasicParleyPermission("x", null);
		svr.setUserRegistry(new FileUserRegistry() {
			@Override
			public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
				return AuthorizationResult.allowed("everything, even for nobody logged in");
			}
		});
		assertTrue(svr.checkPermission(ServerTestSupport.requester(), x, null).isAllowed());

		svr.setUserRegistry(new FileUserRegistry() {
			@Override
			public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
				return null;
			}
		});
		assertEquals(AuthorizationResult.Status.UNAVAILABLE,
				svr.checkPermission(ServerTestSupport.requester(), x, null).getStatus(), "no answer is not a denial");
		assertEquals(AuthorizationResult.Status.DENIED, svr.checkPermission(ServerTestSupport.requester(), null, null).getStatus(),
				"a command that names no permission");
	}
}
