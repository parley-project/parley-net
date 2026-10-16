package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.client.CertificateValidatorDialog;
import us.bringardner.parley.net.client.CertificateValidotorDialog;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.client.SingleCommandResponse;
import us.bringardner.parley.net.server.DefaultRequestContext;
import us.bringardner.parley.net.server.FileBasedAcl.FileBasedPrincipal;
import us.bringardner.parley.net.server.IServer;
import us.bringardner.parley.net.server.Permission;
import us.bringardner.parley.net.server.Server;

/**
 * The misspelled 0.x names are deprecated in 1.0 but must keep working until 2.0.
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
@SuppressWarnings("deprecation")
public class TestDeprecatedNames {

	@Test
	public void testConstants() {
		assertEquals(IGenericResponseCode.REPLY_300_GENERIC_TEMPORARY_OK, IGenericResponseCode.REPLY_300_GENERIC_TEMPOARY_OK);
		assertEquals(IGenericResponseCode.REPLY_400_GENERIC_TEMPORARY_ERROR, IGenericResponseCode.REPLY_400_GENERIC_TEMPOARY_ERROR);
		assertEquals(IServer.AUTHENTICATION_PROVIDER_PROPERTY, IServer.AUTHENTICATOION_PROVIDER_PROPERTY);
		assertEquals(Server.DEFAULT_MAX_IDLE_CONNECTION, Server.DEFAULT_MAX_IDEL_CONNECTION);
	}

	@Test
	public void testPermissions() {
		FileBasedPrincipal p = new FileBasedPrincipal("user");
		p.add(new Permission("A"));
		assertEquals(p.getPermisssions(), p.getPermissions());
	}

	@Test
	public void testClientSeparator() throws Exception {
		try (CommandClient client = new CommandClient()) {
			client.setSeperator("::");
			assertEquals("::", client.getSeparator());
			client.setSeparator("|");
			assertEquals("|", client.getSeperator());
		}
	}

	@Test
	public void testRequestContextSeparator() {
		DefaultRequestContext ctx = new DefaultRequestContext("a|b");
		ctx.setSeperator("|");
		assertEquals("|", ctx.getSeparator());
		assertEquals("a", ctx.getNextToken());

		String saved = DefaultRequestContext.getDefaultSeparator();
		try {
			DefaultRequestContext.setDefaultSeperator(",");
			assertEquals(",", DefaultRequestContext.getDefaultSeparator());
			DefaultRequestContext.setDefaultSeparator(";");
			assertEquals(";", DefaultRequestContext.getDefaultSeperator());
		} finally {
			DefaultRequestContext.setDefaultSeparator(saved);
		}
	}

	@Test
	public void testGreeting() {
		Server svr = new Server(0, "GreetingNames");
		svr.setServerGreating("220 old");
		assertEquals("220 old", svr.getServerGreeting());
		svr.setServerGreeting("220 new");
		assertEquals("220 new", svr.getServerGreating());
	}

	@Test
	public void testReadResonse() throws Exception {
		SingleCommandResponse resp = new SingleCommandResponse();
		resp.readResonse(TestResponses.stub(" ", "200 ok"));
		assertEquals(200, resp.getResponseCode());
	}

	@Test
	public void testDialogClassKept() {
		assertTrue(CertificateValidatorDialog.class.isAssignableFrom(CertificateValidotorDialog.class));
	}
}
