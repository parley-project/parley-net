package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.client.ICommandResponse;

/**
 * CommandClient.executeCommands: commands sent together, replies read in order.
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
public class TestPipelining {

	private static TestServer svr;

	@BeforeAll
	public static void startServer() {
		svr = ServerTestSupport.start(ServerTestSupport.create("PipelineServer", ServerTestSupport.standardCommands(), null));
	}

	@AfterAll
	public static void stopServer() {
		ServerTestSupport.stop(svr);
	}

	@Test
	public void repliesComeBackInOrder() throws Exception {
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			List<ICommandResponse> replies = client.executeCommands(Arrays.asList(
					ServerTestSupport.ECHO + " one", "NoSuchCommand", ServerTestSupport.ECHO + " three"));
			assertEquals(3, replies.size());
			assertTrue(replies.get(0).isPositive());
			assertEquals("one", replies.get(0).getResponseText());
			assertFalse(replies.get(1).isPositive(), "an error reply stays with its command");
			assertEquals("three", replies.get(2).getResponseText());
			// the connection is in step afterwards
			assertEquals("after", client.executeCommand(ServerTestSupport.ECHO, "after").getResponseText());
		}
	}

	@Test
	public void longListsGoInBatches() throws Exception {
		int n = CommandClient.MAX_PIPELINED * 3 + 5;
		List<String> commands = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			commands.add(ServerTestSupport.ECHO + " msg" + i);
		}
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			List<ICommandResponse> replies = client.executeCommands(commands);
			assertEquals(n, replies.size());
			for (int i = 0; i < n; i++) {
				assertEquals("msg" + i, replies.get(i).getResponseText(), "reply " + i);
			}
		}
	}

	@Test
	public void emptyListDoesNothing() throws Exception {
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertTrue(client.executeCommands(new ArrayList<>()).isEmpty());
			assertEquals("still fine", client.executeCommand(ServerTestSupport.ECHO, "still fine").getResponseText());
		}
	}
}
