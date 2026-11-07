package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.credential.ProofCredential;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.net.server.ApopDigest;
import us.bringardner.parley.net.server.ApopVerifier;
import us.bringardner.parley.net.server.FileUserRegistry;
import us.bringardner.parley.net.server.Server;

/** Groups from the user file, and APOP through the server's door. */
public class TestPrincipalGroupsAndApop {

	private static List<String> names(Iterable<ParleyPrincipal> principals) {
		List<String> ret = new ArrayList<String>();
		for (ParleyPrincipal p : principals) {
			ret.add(p.getName());
		}
		return ret;
	}

	@Test
	public void groupsComeFromTheGroupsParameter() throws Exception {
		FileUserRegistry registry = ServerTestSupport.registry(
				"tony@bringardner.us, pw, READ|WRITE, maildrop=t|groups=sales@bringardner.us; support@bringardner.us;sales@bringardner.us",
				"bob@bringardner.us, pw, READ, groups=sales@bringardner.us");
		ParleyPrincipal tony = registry.findPrincipal("tony@bringardner.us");
		assertEquals(Arrays.asList("sales@bringardner.us", "support@bringardner.us"), names(registry.findGroups(tony)), "in order, no duplicates");
		assertNull(tony.getAttribute(FileUserRegistry.PARAMETER_GROUPS), "groups aren't an attribute");
		assertEquals("t", tony.getAttribute("maildrop"));
		ParleyPrincipal bob = registry.findPrincipal("bob@bringardner.us");
		assertEquals(Arrays.asList("sales@bringardner.us"), names(registry.findGroups(bob)));
		assertEquals(registry.findGroups(tony).iterator().next(), registry.findGroups(bob).iterator().next(), "one principal per group");

		// a copy
		registry.findGroups(tony).clear();
		assertEquals(2, registry.findGroups(tony).size());

		// groups hold nothing in a file
		ParleyPrincipal sales = registry.findPrincipal("sales@bringardner.us");
		assertTrue(registry.findPermissions(ServerTestSupport.requester(), sales, null).isEmpty());
		assertTrue(registry.findGroups(sales).isEmpty(), "groups don't nest");
	}

	/** Permission names ignore case now (they were compared exactly before parley-iam). */
	@Test
	public void permissionNamesIgnoreCase() {
		FileUserRegistry registry = ServerTestSupport.registry("a, pw, ADMIN");
		Server svr = new Server(0, "CaseServer-" + System.nanoTime());
		svr.setUserRegistry(registry);
		AuthenticationResult in = ServerTestSupport.login(svr, "a", "pw");
		assertTrue(svr.checkPermission(ServerTestSupport.requester().loggedIn(in), new BasicParleyPermission("admin", null), null).isAllowed());
	}

	@Test
	public void apopIsCheckedThroughTheServer() throws Exception {
		String hashed = FileUserRegistry.hashPassword("pw".toCharArray());
		FileUserRegistry registry = ServerTestSupport.registry("plain, tanstaaf, READ", "hashed, " + hashed + ", READ");
		assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.PLAIN_TEXT));
		String ts = "<1896.697170952@dbc.mtview.ca.us>";
		// RFC 1939's example
		assertEquals("c4c9334bac560ecc979e58001b3e22fb", ApopDigest.digest(ts, "tanstaaf"));

		StoredCredential secret = registry.findStoredCredential("plain", StoredCredentialType.PLAIN_TEXT);
		assertTrue(new ApopVerifier(ts, "c4c9334bac560ecc979e58001b3e22fb").verify(secret));
		assertTrue(new ApopVerifier(ts, "C4C9334BAC560ECC979E58001B3E22FB").verify(secret), "hex in any case");
		assertFalse(new ApopVerifier("<other@x>", "c4c9334bac560ecc979e58001b3e22fb").verify(secret));
		assertFalse(new ApopVerifier(ts, "c4c9334bac560ecc979e58001b3e22fb").verify(null));
		assertFalse(new ApopVerifier(ts, "c4c9334bac560ecc979e58001b3e22fb")
				.verify(new StoredCredential(StoredCredentialType.TSIG_SECRET, "tanstaaf")), "only a plain text secret");
		assertNull(registry.findStoredCredential("hashed", StoredCredentialType.PLAIN_TEXT), "no APOP with a hashed password");

		Server svr = new Server(0, "ApopServer-" + System.nanoTime());
		svr.setUserRegistry(registry);
		AuthenticationResult in = apop(svr, "plain", ts, "c4c9334bac560ecc979e58001b3e22fb");
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus());
		assertEquals("plain", in.getPrincipal().getName());
		assertEquals(StoredCredentialType.PLAIN_TEXT.getName(), in.getMethod());
		assertEquals(AuthenticationResult.Status.REFUSED, apop(svr, "plain", ts, "00").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, apop(svr, "nobody", ts, "c4c9334bac560ecc979e58001b3e22fb").getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, apop(svr, "hashed", ts, ApopDigest.digest(ts, hashed)).getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, apop(svr, null, ts, "00").getStatus());

		FileUserRegistry onlyHashed = ServerTestSupport.registry("hashed, " + hashed + ", READ");
		assertFalse(onlyHashed.supports(ProofCredential.class, StoredCredentialType.PLAIN_TEXT));
	}

	private static AuthenticationResult apop(Server svr, String user, String ts, String digest) {
		return svr.authenticate(new ProofCredential(user, StoredCredentialType.PLAIN_TEXT,
				new ApopVerifier(ts, digest), ServerTestSupport.requester()));
	}
}
