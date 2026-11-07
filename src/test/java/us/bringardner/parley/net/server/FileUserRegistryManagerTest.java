package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.PasswordCredential;
import us.bringardner.parley.iam.BasicParleyPermission;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.PermissionManager;
import us.bringardner.parley.iam.PrincipalManager;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.ProofCredential;
import us.bringardner.parley.iam.ParleyPrincipal;

/** A user file's users and groups found and managed through PrincipalManager. */
public class FileUserRegistryManagerTest {

	@TempDir
	File dir;

	private static final String FILE = "# the users\n"
			+ "alice , secret , READ|WRITE , maildrop=alice\n"
			+ "bob , other , READ , groups=sales\n"
			+ "\n"
			+ "carol , third , READ\n";

	private File users(String text) throws Exception {
		File f = new File(dir, "users.txt");
		Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
		return f;
	}

	private static FileUserRegistry open(File f) throws Exception {
		FileUserRegistry registry = new FileUserRegistry();
		registry.initialize(f);
		return registry;
	}

	private static String read(File f) throws Exception {
		return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
	}

	@Test
	public void groupsAreFoundBothWays() throws Exception {
		try (FileUserRegistry registry = open(users(FILE + "dave , fourth , READ , groups=sales;support\n"))) {
			ParleyPrincipal sales = registry.findPrincipal("sales");
			ParleyPrincipal bob = registry.findPrincipal("bob");
			ParleyPrincipal dave = registry.findPrincipal("dave");
			assertTrue(sales.isGroup());
			assertEquals(Set.of(sales), registry.findGroups(bob));
			assertEquals(2, registry.findGroups(dave).size());
			assertEquals(Set.of(bob, dave), registry.findMembers(sales));
			assertEquals(0, registry.findMembers(bob).size(), "a user has no members");
			assertEquals(0, registry.findGroups(sales).size(), "groups don't nest here");
		}
	}

	@Test
	public void aNewGroupIsKeptOnItsOwnLine() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			PrincipalManager groups = registry;
			ParleyPrincipal support = groups.createGroup("support@bringardner.us");
			assertTrue(support.isGroup());
			assertEquals(0, registry.findMembers(support).size());
			assertTrue(read(f).endsWith("carol , third , READ\ngroup: support@bringardner.us\n"), read(f));

			// another registry reading the same file sees it
			try (FileUserRegistry other = open(f)) {
				ParleyPrincipal found = other.findPrincipal("support@bringardner.us");
				assertNotNull(found);
				assertEquals(support.getId(), found.getId());
			}
		}
	}

	@Test
	public void addingAndRemovingMembersEditsTheUsersLines() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			ParleyPrincipal alice = registry.findPrincipal("alice");
			ParleyPrincipal bob = registry.findPrincipal("bob");
			ParleyPrincipal support = registry.createGroup("support");
			ParleyPrincipal sales = registry.findPrincipal("sales");

			assertTrue(registry.addMember(support, alice));
			assertFalse(registry.addMember(support, alice), "already a member");
			assertTrue(registry.addMember(sales, alice));
			assertTrue(read(f).contains("alice , secret , READ|WRITE , maildrop=alice|groups=support;sales\n"), read(f));
			assertEquals("alice", registry.findPrincipal("alice").getAttribute("maildrop"), "other parameters are kept");
			assertEquals(Set.of(alice, bob), registry.findMembers(sales));

			assertTrue(registry.removeMember(sales, bob));
			assertFalse(registry.removeMember(sales, bob));
			assertTrue(read(f).contains("bob , other , READ\n"), "the groups field goes when it's empty: " + read(f));
			assertEquals(Set.of(alice), registry.findMembers(sales));

			assertTrue(registry.removeMember(sales, alice));
			assertNotNull(registry.findPrincipal("sales"), "a group left empty stays");
			assertTrue(read(f).contains("group: sales\n"), read(f));
			assertTrue(read(f).startsWith("# the users\n"), "comments are kept");
		}
	}

	@Test
	public void deletingAGroupTakesItOffEveryLine() throws Exception {
		File f = users(FILE + "dave , fourth , READ , groups=sales;support\ngroup: sales\n");
		try (FileUserRegistry registry = open(f)) {
			ParleyPrincipal sales = registry.findPrincipal("sales");
			assertTrue(registry.deletePrincipal(sales));
			assertFalse(registry.deletePrincipal(sales));
			assertNull(registry.findPrincipal("sales"));
			String text = read(f);
			assertFalse(text.contains("sales"), text);
			assertTrue(text.contains("dave , fourth , READ , groups=support\n"), text);
		}
	}

	@Test
	public void changesThatCantWorkAreRefused() throws Exception {
		try (FileUserRegistry registry = open(users(FILE))) {
			final PrincipalManager groups = registry;
			final ParleyPrincipal sales = registry.findPrincipal("sales");
			final ParleyPrincipal alice = registry.findPrincipal("alice");
			final ParleyPrincipal support = registry.createGroup("support");
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					groups.createGroup("alice");
				}
			}, "the name of a user");
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					groups.createGroup("sales");
				}
			}, "the name of a group");
			for (final String bad : Arrays.asList("a,b", "a;b", "a|b", "a=b", " a", "#a", "")) {
				assertRefused(new Executable() {
					@Override
					public void execute() throws Throwable {
						groups.createGroup(bad);
					}
				}, "a name the file can't hold: '" + bad + "'");
			}
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					groups.addMember(sales, support);
				}
			}, "groups don't nest");
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					groups.addMember(alice, alice);
				}
			}, "a user isn't a group");
		}
	}

	@Test
	public void usersFromAClassPathResourceCantBeChanged() throws Exception {
		try (final FileUserRegistry registry = new FileUserRegistry()) {
			registry.parseLine("bob , other , READ , groups=sales");
			final ParleyPrincipal sales = registry.findPrincipal("sales");
			assertNotNull(sales);
			assertThrows(UnsupportedOperationException.class, new Executable() {
				@Override
				public void execute() throws Throwable {
					registry.deletePrincipal(sales);
				}
			});
		}
	}

	@Test
	public void theFileKeepsItsPermissions() throws Exception {
		File f = users(FILE);
		PosixFileAttributeView view = Files.getFileAttributeView(f.toPath(), PosixFileAttributeView.class);
		if (view == null) {
			return; // no POSIX permissions on this file system
		}
		Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
		Files.setPosixFilePermissions(f.toPath(), ownerOnly);
		try (FileUserRegistry registry = open(f)) {
			registry.createGroup("support");
		}
		assertEquals(ownerOnly, Files.getPosixFilePermissions(f.toPath()));
		assertEquals(1, dir.list().length, "no temporary file is left: " + Arrays.toString(dir.list()));
	}

	@Test
	public void withGroupsKeepsTheOtherFields() {
		List<String> none = new ArrayList<String>();
		assertEquals("a , p , READ , groups=x", FileUserRegistry.withGroups("a , p , READ", Arrays.asList("x")));
		assertEquals("a , p , READ , groups=x;y", FileUserRegistry.withGroups("a , p , READ ", Arrays.asList("x", "y")));
		assertEquals("a , p , READ , m=1|groups=y", FileUserRegistry.withGroups("a , p , READ , m=1|groups=x", Arrays.asList("y")));
		assertEquals("a , p , READ , m=1", FileUserRegistry.withGroups("a , p , READ , groups=x|m=1", none));
		assertEquals("a , p , READ", FileUserRegistry.withGroups("a , p , READ , groups=x", none));
		assertEquals("a , p , READ , , extra", FileUserRegistry.withGroups("a , p , READ , groups=x, extra", none));
	}

	private static AuthenticationResult.Status login(FileUserRegistry registry, String user, String password) {
		Requester r = Requester.connected(null, 110, true, Requester.Transport.TCP, "pop3");
		return registry.authenticate(new PasswordCredential(user, password.toCharArray(), r)).getStatus();
	}

	@Test
	public void usersAreManagedThroughTheFile() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			PrincipalManager manager = registry;
			ParleyPrincipal jose = manager.createUser("jose@bringardner.us");
			assertTrue(read(f).endsWith("jose@bringardner.us , , \n"), read(f));
			assertEquals(AuthenticationResult.Status.REFUSED, login(registry, "jose@bringardner.us", ""), "no password: no login, not even an empty one");

			manager.setPassword(jose, "pw".toCharArray());
			assertTrue(read(f).contains("jose@bringardner.us , {PBKDF2}"), read(f));
			assertEquals(AuthenticationResult.Status.AUTHENTICATED, login(registry, "jose@bringardner.us", "pw"));

			ParleyPrincipal changed = manager.setAttribute(jose, "maildrop", "jose");
			assertEquals("jose", changed.getAttribute("maildrop"));
			assertEquals(jose, changed);
			assertEquals(null, manager.setAttribute(jose, "maildrop", null).getAttribute("maildrop"));

			assertTrue(manager.removePassword(jose));
			assertFalse(manager.removePassword(jose));
			assertEquals(AuthenticationResult.Status.REFUSED, login(registry, "jose@bringardner.us", "pw"));

			assertTrue(manager.deletePrincipal(jose));
			assertFalse(read(f).contains("jose"), read(f));
			assertNull(registry.findPrincipal("jose@bringardner.us"));
		}
	}

	@Test
	public void aNewUserDoesntTurnScramOff() throws Exception {
		File f = users("a , " + FileUserRegistry.hashPasswordWithScram("pw".toCharArray()) + " , READ\n");
		try (FileUserRegistry registry = open(f)) {
			assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256));
			registry.createUser("b");
			assertTrue(registry.supports(ProofCredential.class, StoredCredentialType.SCRAM_SHA_256), "b has no password, so it doesn't count");
		}
	}

	@Test
	public void aTurnedOffUserIsAsIfGone() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			ParleyPrincipal bob = registry.findPrincipal("bob");
			ParleyPrincipal sales = registry.findPrincipal("sales");
			registry.setEnabled(bob, false);
			assertTrue(read(f).contains("bob , other , READ , groups=sales|enabled=false\n"), read(f));
			assertFalse(registry.isEnabled(bob));
			assertTrue(registry.isEnabled(sales), "a group is always on");
			assertEquals(AuthenticationResult.Status.REFUSED, login(registry, "bob", "other"));
			assertNull(registry.findPrincipal("bob"));
			assertNull(registry.findPrincipal(bob.getId()));
			assertEquals(0, registry.findMembers(sales).size());
			assertEquals(java.util.List.of(bob), registry.findPrincipals("b", PrincipalManager.Kind.USER, 0), "listed, so it can be turned on");
			assertEquals(null, bob.getAttribute("enabled"), "not an attribute");

			registry.setEnabled(bob, true);
			assertTrue(read(f).contains("bob , other , READ , groups=sales\n"), read(f));
			assertEquals(AuthenticationResult.Status.AUTHENTICATED, login(registry, "bob", "other"));
		}
	}

	@Test
	public void groupsHaveAttributesOnTheirOwnLine() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			ParleyPrincipal sales = registry.findPrincipal("sales");
			ParleyPrincipal changed = registry.setAttribute(sales, "mailbox", "Sales");
			assertEquals("Sales", changed.getAttribute("mailbox"));
			assertTrue(read(f).endsWith("group: sales , mailbox=Sales\n"), read(f));
			ParleyPrincipal bob = registry.findPrincipal("bob");
			assertEquals("Sales", registry.findGroups(bob).iterator().next().getAttribute("mailbox"), "found through a member too");
			registry.setAttribute(sales, "mailbox", "S2");
			assertTrue(read(f).endsWith("group: sales , mailbox=S2\n"), read(f));
			registry.setAttribute(sales, "mailbox", null);
			assertTrue(read(f).endsWith("group: sales\n"), read(f));
			assertNotNull(registry.findPrincipal("sales"));
		}
	}

	@Test
	public void principalsAreListedByName() throws Exception {
		try (FileUserRegistry registry = open(users(FILE + "group: support\n"))) {
			assertEquals(java.util.List.of("alice", "bob", "carol", "sales", "support"),
					names(registry.findPrincipals(null, PrincipalManager.Kind.ANY, 0)));
			assertEquals(java.util.List.of("sales", "support"), names(registry.findPrincipals("", PrincipalManager.Kind.GROUP, 0)));
			assertEquals(java.util.List.of("sales"), names(registry.findPrincipals("s", PrincipalManager.Kind.ANY, 1)), "the limit");
			assertEquals(0, registry.findPrincipals("S", PrincipalManager.Kind.ANY, 0).size(), "case counts here");
		}
	}

	@Test
	public void attributesTheFileCantHoldAreRefused() throws Exception {
		try (FileUserRegistry registry = open(users(FILE))) {
			final ParleyPrincipal alice = registry.findPrincipal("alice");
			for (final String[] bad : new String[][] { { "groups", "x" }, { "enabled", "false" }, { "a", "b,c" }, { "a", "b|c" },
					{ "a", "b=c" }, { "a", "" }, { "a b ", "c" } }) {
				assertRefused(new Executable() {
					@Override
					public void execute() throws Throwable {
						registry.setAttribute(alice, bad[0], bad[1]);
					}
				}, bad[0] + "=" + bad[1]);
			}
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					registry.setPassword(registry.findPrincipal("sales"), "pw".toCharArray());
				}
			}, "a group doesn't log in");
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					registry.createUser("sales");
				}
			}, "the name of a group");
		}
	}

	@Test
	public void grantsToUsersAreKeptInThePermissionsField() throws Exception {
		File f = users(FILE);
		try (FileUserRegistry registry = open(f)) {
			final PermissionManager manager = registry;
			final ParleyPrincipal carol = registry.findPrincipal("carol");
			final ParleyPrincipal sales = registry.findPrincipal("sales");
			ParleyPermission write = new BasicParleyPermission("write", null);
			assertTrue(manager.supportsGrant(false, false));
			assertFalse(manager.supportsGrant(true, false), "no grants to groups here");
			assertFalse(manager.supportsGrant(false, true), "no grants about one resource here");

			assertTrue(manager.grant(carol, write));
			assertFalse(manager.grant(carol, new BasicParleyPermission("WRITE", null)), "names ignore case");
			assertTrue(read(f).contains("carol , third , READ|write\n"), read(f));
			assertEquals(2, manager.findGrants(carol).size());
			assertEquals(0, manager.findGrants(sales).size(), "a group holds none here");

			assertTrue(manager.revoke(carol, new BasicParleyPermission("Read", null)));
			assertFalse(manager.revoke(carol, new BasicParleyPermission("read", null)));
			assertTrue(read(f).contains("carol , third , write\n"), read(f));
			assertTrue(manager.revoke(carol, write));
			assertTrue(read(f).contains("carol , third , \n"), read(f));
			assertEquals(0, manager.findGrants(carol).size());
			assertNotNull(registry.findPrincipal("carol"), "a user with no permissions is still a user");

			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					manager.grant(sales, new BasicParleyPermission("read", null));
				}
			}, "a grant to a group");
			assertRefused(new Executable() {
				@Override
				public void execute() throws Throwable {
					manager.grant(carol, new BasicParleyPermission("read", EntityId.of("mailbox:carol/INBOX")));
				}
			}, "a grant about one resource");
		}
	}

	private static List<String> names(List<ParleyPrincipal> principals) {
		List<String> ret = new ArrayList<String>();
		for (ParleyPrincipal p : principals) {
			ret.add(p.getName());
		}
		return ret;
	}

	private static void assertRefused(Executable change, String why) {
		assertThrows(IllegalArgumentException.class, change, why);
	}
}
