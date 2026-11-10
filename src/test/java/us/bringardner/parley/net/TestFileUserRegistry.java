package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import us.bringardner.parley.core.LogLevel;
import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.PropertiesUserRegistry;
import us.bringardner.parley.net.server.Server;

/**
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
public class TestFileUserRegistry {

	@AfterEach
	public void clearProperties() {
		// System properties are JVM wide, don't leak them into other tests
		System.clearProperty("TestSetver."+IServer.AUTHENTICATION_PROVIDER_PROPERTY);
		System.clearProperty("TestSetver.user0");
		System.clearProperty("TestSetver.user1");
		System.clearProperty("TestSetver.userFile");
	}

	@Test
	public void testPropertiesUserRegistry() throws Exception {
		String serverName = "TestSetver";

		System.setProperty(serverName+"."+IServer.AUTHENTICATION_PROVIDER_PROPERTY, PropertiesUserRegistry.class.getCanonicalName());
		System.setProperty(serverName+".user0","echoUser, password  , Echo|Login, key1=val1|key2=val2");
		System.setProperty(serverName+".user1","user1  , password   , one|two|three|four|five, key3=val3|key4=val4");
		validateRegistry(serverName, PropertiesUserRegistry.class);
	}

	@Test
	public void testFileUserRegistry() throws Exception {
		String serverName = "TestSetver";

		System.setProperty(serverName+"."+IServer.AUTHENTICATION_PROVIDER_PROPERTY, FileUserRegistry.class.getCanonicalName());
		System.setProperty(serverName+".userFile","FileBasedAcl.txt");

		validateRegistry(serverName, FileUserRegistry.class);
	}

	/** Set up by name, without a server */
	@Test
	public void testInitializeByName() throws Exception {
		String serverName = "TestSetver";
		System.setProperty(serverName+".user0","echoUser, password  , Echo|Login, key1=val1|key2=val2");
		System.setProperty(serverName+".user1","user1  , password   , one|two|three|four|five, key3=val3|key4=val4");
		PropertiesUserRegistry registry = new PropertiesUserRegistry();
		registry.initialize(serverName);
		final ParleyPrincipal p = registry.findPrincipal("user1");
		assertNotNull(p, "user1 not found");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, ServerTestSupport.login(registry, "user1", "password").getStatus());

		System.setProperty(serverName+".userFile","FileBasedAcl.txt");
		FileUserRegistry file = new FileUserRegistry();
		file.initialize(serverName);
		assertNotNull(file.findPrincipal("echoUser"), "echoUser not found");

		// The principals it hands out can't be changed
		assertThrows(UnsupportedOperationException.class, new Executable() {
			@Override
			public void execute() {
				p.getAttributeNames().clear();
			}
		});
		file.close();
		registry.close();
	}

	/** Ids come from the names; the file can't keep any other. */
	@Test
	public void idsComeFromNames() throws Exception {
		FileUserRegistry registry = ServerTestSupport.registry("tony, pw, READ, groups=sales", "bob, pw, READ");
		ParleyPrincipal tony = registry.findPrincipal("tony");
		assertEquals(EntityId.of(FileUserRegistry.USER_ID_PREFIX+"tony"), tony.getId());
		assertFalse(tony.isGroup());
		assertSame(tony, registry.findPrincipal(tony.getId()));
		ParleyPrincipal sales = registry.findPrincipal("sales");
		assertTrue(sales.isGroup());
		assertEquals(EntityId.of(FileUserRegistry.GROUP_ID_PREFIX+"sales"), sales.getId());
		assertSame(sales, registry.findPrincipal(sales.getId()));
		assertNull(registry.findPrincipal(EntityId.of("user:nobody")));
		assertNull(registry.findPrincipal("Tony"), "names are matched exactly");
		assertNull(registry.findPrincipal((String) null));
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(registry, "sales", "pw").getStatus(), "a group can't log in");
	}

	/** The permissions are on the server as a whole, and the server's authorizer reads them. */
	@Test
	public void permissionsAreServerWide() throws Exception {
		FileUserRegistry registry = ServerTestSupport.registry("tony, pw, Read|smtp.send");
		ParleyPrincipal tony = registry.findPrincipal("tony");
		Requester nobody = ServerTestSupport.requester();
		assertEquals(Arrays.asList("Read", "smtp.send"), ServerTestSupport.names(registry.findPermissions(nobody, tony, null)));
		ProtectedResource file = new ProtectedResource() {
			@Override
			public EntityId getId() {
				return EntityId.of("file:1");
			}

			@Override
			public String getType() {
				return "file";
			}

			@Override
			public String getName() {
				return "/notes.txt";
			}

			@Override
			public EntityId getOwnerId() {
				return EntityId.of("user:someone");
			}
		};
		assertTrue(registry.findPermissions(nobody, tony, file).isEmpty(), "nothing on a resource");

		Server svr = new Server(0, "PermServer-" + System.nanoTime());
		svr.setUserRegistry(registry);
		AuthenticationResult in = ServerTestSupport.login(svr, "tony", "pw");
		Requester tonyIn = nobody.loggedIn(in);
		assertTrue(svr.checkPermission(tonyIn, new BasicParleyPermission("read", null), null).isAllowed(), "names ignore case");
		assertEquals(AuthorizationResult.Status.DENIED, svr.checkPermission(tonyIn, new BasicParleyPermission("write", null), null).getStatus());
		assertEquals(AuthorizationResult.Status.DENIED, svr.checkPermission(nobody, new BasicParleyPermission("Read", null), null).getStatus(), "not logged in");
		assertEquals(AuthorizationResult.Status.DENIED, svr.checkPermission(tonyIn, new BasicParleyPermission("Read", EntityId.of("file:1")), file).getStatus());
	}

	private void validateRegistry(String serverName, Class<?> expected) throws Exception {
		Server svr = new Server(1000, serverName);
		svr.setLogLevel(LogLevel.WARN);
		UserRegistry registry = svr.getUserRegistry();
		assertNotNull(registry, "the registry was not found");
		assertEquals(expected, registry.getClass());
		Requester nobody = ServerTestSupport.requester();

		/*
			user1  , password   , one|two|three|four|five, key=val|key=val
			echoUser, password  , Echo|Login, key1=val1|key2=val2

		 */
		AuthenticationResult in = ServerTestSupport.login(svr, "user1", "password");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus(), "user1 was not authenticated");
		assertEquals(FileUserRegistry.PASSWORD_METHOD, in.getMethod());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "user1", "wrong").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, ServerTestSupport.login(svr, "nobody", "password").getStatus());

		ParleyPrincipal p = in.getPrincipal();
		assertEquals("user1", p.getName());
		assertEquals(Arrays.asList("one","two","three","four","five"), ServerTestSupport.names(((FileUserRegistry) registry).findPermissions(nobody, p, null)));
		assertEquals("val3", p.getAttribute("key3"),"Wrong parameter value for key3");
		assertEquals("val4", p.getAttribute("key4"),"Wrong parameter value for key4");
		assertEquals(Collections.emptySet(), ((FileUserRegistry) registry).findGroups(p));

		in = ServerTestSupport.login(svr, "echoUser", "password");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus(), "echoUser was not authenticated");
		p = in.getPrincipal();
		assertEquals(Arrays.asList("Echo","Login"), ServerTestSupport.names(((FileUserRegistry) registry).findPermissions(nobody, p, null)));
		assertEquals("val1", p.getAttribute("key1"),"Wrong parameter value for key1");
		assertEquals("val2", p.getAttribute("key2"),"Wrong parameter value for key2");
	}

}
