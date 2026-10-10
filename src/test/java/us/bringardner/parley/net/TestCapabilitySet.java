package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.capability.Capability;
import us.bringardner.parley.net.capability.CapabilityRegistry;
import us.bringardner.parley.net.capability.CapabilitySet;
import us.bringardner.parley.net.client.MultiLineCommandResponse;
import us.bringardner.parley.net.server.ICommandProcessor;

/**
 * Capabilities: building, rendering for each protocol style, parsing, and the registry.
 */
public class TestCapabilitySet {

	@Test
	public void lookupIgnoresCase() {
		CapabilitySet set = new CapabilitySet().add("SIZE", "35882577").add("8BITMIME");
		assertTrue(set.has("size"));
		assertTrue(set.has("Size", "35882577"));
		assertFalse(set.has("SIZE", "1"));
		assertFalse(set.has("STARTTLS"));
		assertEquals(Arrays.asList("35882577"), set.getParams("size"));
		assertEquals(Collections.emptyList(), set.getParams("nothing"));
		assertNull(set.get("nothing"));
		assertEquals(2, set.size());
	}

	@Test
	public void sameNameMergesParameters() {
		CapabilitySet set = new CapabilitySet().add("AUTH", "PLAIN").add("auth", "LOGIN", "plain");
		assertEquals(1, set.size());
		assertEquals(Arrays.asList("PLAIN", "LOGIN"), set.getParams("AUTH"));
		assertEquals("AUTH", set.get("auth").getName(), "the first spelling is kept");
	}

	@Test
	public void rendersOneCapabilityPerLine() {
		CapabilitySet set = new CapabilitySet().add("PIPELINING").add("AUTH", "PLAIN", "LOGIN")
				.addIf(false, "STARTTLS").addIf(true, "SIZE", "100");
		assertEquals(Arrays.asList("PIPELINING", "AUTH PLAIN LOGIN", "SIZE 100"), set.toLines());
	}

	@Test
	public void rendersImapStyleInline() {
		CapabilitySet set = new CapabilitySet().add("IMAP4rev1").add("STARTTLS").add("AUTH", "PLAIN", "LOGIN");
		assertEquals("IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN", set.toInline());
	}

	@Test
	public void parsesLines() {
		CapabilitySet set = CapabilitySet.parseLines(Arrays.asList(" MLST size*;type*", "UTF8", "", "SASL PLAIN  SCRAM"));
		assertEquals(Arrays.asList("size*;type*"), set.getParams("MLST"));
		assertTrue(set.has("utf8"));
		assertEquals(Arrays.asList("PLAIN", "SCRAM"), set.getParams("SASL"));
		assertEquals(3, set.size());
	}

	@Test
	public void parsesInline() {
		CapabilitySet set = CapabilitySet.parseInline("IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=SCRAM-SHA-256 X=a=b");
		assertTrue(set.has("imap4rev1"));
		assertTrue(set.has("AUTH", "SCRAM-SHA-256"));
		assertEquals(Arrays.asList("PLAIN", "SCRAM-SHA-256"), set.getParams("AUTH"));
		assertEquals(Arrays.asList("a=b"), set.getParams("X"), "only the first '=' splits");
	}

	@Test
	public void roundTripsBothStyles() {
		CapabilitySet set = new CapabilitySet().add("A").add("B", "1", "2");
		assertEquals(set.toLines(), CapabilitySet.parseLines(set.toLines()).toLines());
		assertEquals(set.toInline(), CapabilitySet.parseInline(set.toInline()).toInline());
	}

	@Test
	public void parsesEhloAndFeatReplies() throws Exception {
		MultiLineCommandResponse ehlo = new MultiLineCommandResponse();
		ehlo.readResponse(TestResponses.stub(" ", "250-mail.example.com greets you", "250-SIZE 1000",
				"250-AUTH PLAIN LOGIN", "250 PIPELINING"));
		CapabilitySet smtp = CapabilitySet.parseReply(ehlo, 1, 0);
		assertEquals(3, smtp.size());
		assertTrue(smtp.has("AUTH", "LOGIN"));
		assertTrue(smtp.has("PIPELINING"));

		MultiLineCommandResponse feat = new MultiLineCommandResponse();
		feat.readResponse(TestResponses.stub(" ", "211-Features:", "211-" + " MLST size*;type*", "211-" + " UTF8",
				"211 End"));
		CapabilitySet ftp = CapabilitySet.parseReply(feat, 1, 1);
		assertEquals(2, ftp.size());
		assertTrue(ftp.has("UTF8"));
		assertFalse(ftp.has("End"));
	}

	@Test
	public void capabilityEquality() {
		assertEquals(new Capability("auth", "PLAIN"), new Capability("AUTH", "PLAIN"));
		assertEquals("AUTH PLAIN", new Capability("AUTH", "PLAIN").toString());
	}

	@Test
	public void registryResolvesPerSession() {
		boolean[] tls = {false};
		CapabilityRegistry registry = new CapabilityRegistry()
				.add("PIPELINING")
				.addWhen(p -> !tls[0], "STARTTLS")
				.addDynamic("AUTH", p -> tls[0] ? Arrays.asList("PLAIN", "LOGIN") : null)
				.addDynamicRequireParams("SASL", p -> Collections.<String>emptyList());
		ICommandProcessor processor = null; // the conditions above don't use it

		CapabilitySet before = registry.resolve(processor);
		assertEquals(Arrays.asList("PIPELINING", "STARTTLS"), before.toLines());

		tls[0] = true;
		CapabilitySet after = registry.resolve(processor);
		assertEquals(Arrays.asList("PIPELINING", "AUTH PLAIN LOGIN"), after.toLines());
	}
}
