package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.BasicParleyPermission;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.Server;

/**
 * Server runtime values, and logging in and authorizing through a server.
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
public class TestPrincipalsAndValues {

	private static final ParleyPermission A = new BasicParleyPermission("A", null);
	private static final ParleyPermission B = new BasicParleyPermission("B", null);

	@Test
	public void testRuntimeValues() {
		Server svr = new Server(0, "ValuesServer");
		svr.setRuntimeValue("a", 1);
		assertEquals(1, svr.getRuntimeValue("a"));
		svr.setRuntimeValue("a", null);
		assertNull(svr.getRuntimeValue("a"), "a null value removes the entry");
		svr.setRuntimeValue(null, 1);
		assertNull(svr.getRuntimeValue(null));
		assertNull(svr.removeRuntimeValue(null));

		Map<String, Object> values = new HashMap<>();
		values.put("b", 2);
		values.put("c", null);
		svr.setRuntimeValues(values);
		assertEquals(2, svr.getRuntimeValue("b"));
		assertNull(svr.getRuntimeValue("c"));
		assertEquals(2, svr.removeRuntimeValue("b"));
		assertTrue(svr.getRuntimeValues().isEmpty());

		svr.setRuntimeValues(null);
		assertNotNull(svr.getRuntimeValues());
	}

	@Test
	public void testAuthenticateAndAuthorize() {
		String hash = FileUserRegistry.hashPassword("pw".toCharArray());
		Server svr = new Server(0, "AuthServer");
		svr.setUserRegistry(ServerTestSupport.registry("hashed, " + hash + ", A", "plain, plainpw, B"));

		AuthenticationResult in = ServerTestSupport.login(svr, "hashed", "pw");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus());
		ParleyPrincipal hashed = in.getPrincipal();
		assertEquals("hashed", hashed.getName());
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(svr, "plain", "plainpw").getStatus());

		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "hashed", "wrong").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "nobody", "pw").getStatus(), "unknown user");

		Requester nobody = ServerTestSupport.requester();
		Requester requester = nobody.loggedIn(in);
		assertTrue(svr.checkPermission(requester, A, null).isAllowed());
		assertFalse(svr.checkPermission(requester, B, null).isAllowed());
		assertFalse(svr.checkPermission(nobody, A, null).isAllowed(), "not logged in");
		assertEquals(1, requester.getMethods().size());
		assertEquals(FileUserRegistry.PASSWORD_METHOD, requester.getMethods().get(0));
	}

	@Test
	public void testNoUserRegistry() {
		Server svr = new Server(0, "NoAclServer-" + System.nanoTime());
		AuthenticationResult result = ServerTestSupport.login(svr, "anyone", "pw");
		assertEquals(AuthenticationResult.Status.UNSUPPORTED, result.getStatus());
		assertEquals("no user registry", result.getReason());
		AuthorizationResult check = svr.checkPermission(ServerTestSupport.requester(), A, null);
		assertEquals(AuthorizationResult.Status.DENIED, check.getStatus());
		assertEquals("no user registry", check.getReason());
		assertNull(svr.getUserRegistry());
	}
}
