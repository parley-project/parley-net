package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.server.ApopDigest;
import us.bringardner.parley.net.server.FileBasedAcl;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.ImmutablePrincipal;
import us.bringardner.parley.net.server.Permission;
import us.bringardner.parley.net.server.Server;

/** The identity half of IPrincipal (groups) and the checks that stay in the list (APOP). */
public class TestPrincipalGroupsAndApop {

	@Test
	public void groupsComeFromTheGroupsParameter() throws Exception {
		FileBasedAcl acl = (FileBasedAcl) ServerTestSupport.acl(
				"tony@bringardner.us, pw, READ|WRITE, maildrop=t|groups=sales@bringardner.us; support@bringardner.us;sales@bringardner.us",
				"bob@bringardner.us, pw, READ");
		IPrincipal tony = acl.getPrincipal("tony@bringardner.us");
		assertEquals(Arrays.asList("sales@bringardner.us", "support@bringardner.us"), tony.getGroups(), "in order, no duplicates");
		assertNull(tony.getParameter(FileBasedAcl.PARAMETER_GROUPS), "groups aren't a parameter");
		assertEquals("t", tony.getParameter("maildrop"));
		assertEquals(Collections.emptyList(), acl.getPrincipal("bob@bringardner.us").getGroups());

		// a copy
		tony.getGroups().clear();
		assertEquals(2, tony.getGroups().size());

		IPrincipal ro = new ImmutablePrincipal(tony);
		assertEquals(tony.getGroups(), ro.getGroups());
		assertThrows(UnsupportedOperationException.class, () -> ro.getGroups().add("x"));
	}

	@Test
	public void permissionNamesAreCaseSensitive() {
		FileBasedAcl acl = (FileBasedAcl) ServerTestSupport.acl("a, pw, ADMIN");
		IPrincipal p = acl.getPrincipal("a");
		assertTrue(p.hasPermission(new Permission("ADMIN")));
		assertFalse(p.hasPermission(new Permission("admin")));
	}

	@Test
	public void apopIsCheckedInTheList() throws Exception {
		String hashed = FileBasedAcl.hashPassword("pw".toCharArray());
		FileBasedAcl acl = (FileBasedAcl) ServerTestSupport.acl("plain, tanstaaf, READ", "hashed, " + hashed + ", READ");
		assertTrue(acl.supportsApop());
		String ts = "<1896.697170952@dbc.mtview.ca.us>";
		// RFC 1939's example
		assertEquals("c4c9334bac560ecc979e58001b3e22fb", ApopDigest.digest(ts, "tanstaaf"));
		IPrincipal p = acl.getPrincipal("plain");
		assertTrue(acl.verifyApop(p, ts, "c4c9334bac560ecc979e58001b3e22fb"));
		assertTrue(acl.verifyApop(p, ts, "C4C9334BAC560ECC979E58001B3E22FB"), "hex in any case");
		assertTrue(acl.verifyApop(new ImmutablePrincipal(p), ts, "c4c9334bac560ecc979e58001b3e22fb"), "a read only view");
		assertFalse(acl.verifyApop(p, "<other@x>", "c4c9334bac560ecc979e58001b3e22fb"));
		assertFalse(acl.verifyApop(acl.getPrincipal("hashed"), ts, ApopDigest.digest(ts, hashed)), "no APOP with a hashed password");
		assertFalse(acl.verifyApop(null, ts, "x"));

		Server svr = new Server(0, "ApopServer-" + System.nanoTime());
		svr.setAccessControl(acl);
		IPrincipal in = svr.checkApopLogin("plain", ts, "c4c9334bac560ecc979e58001b3e22fb");
		assertNotNull(in);
		assertEquals(IPrincipal.State.Authenticated, in.getState());
		assertThrows(UnsupportedOperationException.class, () -> in.add(new Permission("WRITE")));
		assertNull(svr.checkApopLogin("plain", ts, "00"));
		assertNull(svr.checkApopLogin("nobody", ts, "c4c9334bac560ecc979e58001b3e22fb"));

		FileBasedAcl onlyHashed = (FileBasedAcl) ServerTestSupport.acl("hashed, " + hashed + ", READ");
		assertFalse(onlyHashed.supportsApop());
	}
}
