package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.sasl.ISaslClient;
import us.bringardner.parley.net.sasl.SaslClients;

/**
 * Choosing a client mechanism from what a server offers.
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
public class TestSaslClients {

	@Test
	public void createsEachPasswordMechanismInAnyCase() {
		for (String name : SaslClients.STRONGEST_FIRST) {
			assertTrue(SaslClients.isSupported(name.toLowerCase()));
			ISaslClient c = SaslClients.create(name.toLowerCase(), "u", "p");
			assertNotNull(c, name);
			assertEquals(name, c.getName());
		}
		assertFalse(SaslClients.isSupported("XOAUTH2"));
		assertNull(SaslClients.create("XOAUTH2", "u", "p"));
		assertNull(SaslClients.create(null, "u", "p"));
	}

	@Test
	public void thePreferenceListDecidesNotTheServersOrder() {
		java.util.List<String> offered = Arrays.asList("PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256");
		assertEquals("SCRAM-SHA-256", SaslClients.choose(offered, SaslClients.STRONGEST_FIRST, "u", "p").getName());
		assertEquals("PLAIN", SaslClients.choose(offered, Arrays.asList("PLAIN", "SCRAM-SHA-256"), "u", "p").getName());
	}

	@Test
	public void returnsNullWhenNothingMatches() {
		assertNull(SaslClients.choose(Arrays.asList("GSSAPI", "XOAUTH2"), SaslClients.STRONGEST_FIRST, "u", "p"));
		assertNull(SaslClients.choose(Arrays.asList("PLAIN"), Arrays.asList("SCRAM-SHA-256"), "u", "p"));
		assertNull(SaslClients.choose(Collections.<String>emptyList(), SaslClients.STRONGEST_FIRST, "u", "p"));
		assertNull(SaslClients.choose(Arrays.asList("PLAIN"), Collections.<String>emptyList(), "u", "p"));
	}

	@Test
	public void matchesOfferedNamesInAnyCase() {
		assertEquals("SCRAM-SHA-256", SaslClients.choose(Arrays.asList("scram-sha-256"),
				Arrays.asList("SCRAM-SHA-256"), "u", "p").getName());
	}
}
