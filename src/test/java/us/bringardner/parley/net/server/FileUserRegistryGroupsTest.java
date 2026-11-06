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

import us.bringardner.parley.iam.GroupManager;
import us.bringardner.parley.iam.ParleyPrincipal;

/** A user file's groups found and changed through GroupManager. */
public class FileUserRegistryGroupsTest {

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
			GroupManager groups = registry;
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
			assertTrue(registry.deleteGroup(sales));
			assertFalse(registry.deleteGroup(sales));
			assertNull(registry.findPrincipal("sales"));
			String text = read(f);
			assertFalse(text.contains("sales"), text);
			assertTrue(text.contains("dave , fourth , READ , groups=support\n"), text);
			assertFalse(registry.deleteGroup(registry.findPrincipal("carol")), "a user isn't deleted as a group");
			assertNotNull(registry.findPrincipal("carol"));
		}
	}

	@Test
	public void changesThatCantWorkAreRefused() throws Exception {
		try (FileUserRegistry registry = open(users(FILE))) {
			final GroupManager groups = registry;
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
					registry.deleteGroup(sales);
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

	private static void assertRefused(Executable change, String why) {
		assertThrows(IllegalArgumentException.class, change, why);
	}
}
