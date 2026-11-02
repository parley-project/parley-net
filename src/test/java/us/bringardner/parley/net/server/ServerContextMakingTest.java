package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** ServerContext.making: a server knows its launcher id while it is made (To-Do 3.6) */
public class ServerContextMakingTest {

	@Test
	public void theIdIsKnownOnlyWhileTheServerIsMade() throws Exception {
		ServerContext c = new ServerContext();
		assertNull(c.getServerIdBeingMade());
		String seen = c.making("imaps", () -> {
			assertEquals("smtp", c.making("smtp", c::getServerIdBeingMade), "nested");
			return c.getServerIdBeingMade();
		});
		assertEquals("imaps", seen, "and back to the outer one after the nested call");
		assertNull(c.getServerIdBeingMade(), "forgotten afterwards");
		Thread t = new Thread(() -> {
			try {
				c.making("pop3", () -> {
					assertEquals("pop3", c.getServerIdBeingMade());
					return null;
				});
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		t.start();
		t.join();
		assertNull(c.getServerIdBeingMade(), "per thread");
		c.close();
	}
}
