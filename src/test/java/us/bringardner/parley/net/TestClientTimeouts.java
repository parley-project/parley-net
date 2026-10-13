package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.client.Client;
import us.bringardner.parley.net.client.CommandClient;

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
public class TestClientTimeouts {

	private static final String READ = CommandClient.class.getName()+"."+Client.PROPERTY_READ_TIMEOUT;
	private static final String CONNECT = CommandClient.class.getName()+"."+Client.PROPERTY_CONNECT_TIMEOUT;

	@Test
	public void testDefaults() {
		try(CommandClient client = new CommandClient("localhost", 1)) {
			assertEquals(Client.getDefaultReadTimeout(), client.getTimeout());
			assertEquals(Client.DEFAULT_CONNECT_TIMEOUT, client.getConnectTimeout());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void testProperties() throws Exception {
		System.setProperty(READ, "1234");
		System.setProperty(CONNECT, "567");
		try(CommandClient client = new CommandClient("localhost", 1)) {
			assertEquals(1234, client.getTimeout());
			assertEquals(567, client.getConnectTimeout());

			// explicit calls win
			client.setTimeout(0);
			assertEquals(0, client.getTimeout());
		} finally {
			System.clearProperty(READ);
			System.clearProperty(CONNECT);
		}
	}

	@Test
	public void testInvalidPropertyUsesDefault() throws Exception {
		System.setProperty(READ, "five minutes");
		try(CommandClient client = new CommandClient("localhost", 1)) {
			assertEquals(Client.getDefaultReadTimeout(), client.getTimeout());
		} finally {
			System.clearProperty(READ);
		}
	}
}
