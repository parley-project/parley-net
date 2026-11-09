package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.net.TestFiles;

/** On the local file system and on a memory file system (To-Do 18.8 C6) */
public class PropertiesDomainListTest {

	@TempDir
	Path tempDir;

	private FileSource dir;

	private void on(String type) throws IOException {
		dir = TestFiles.folder(type, tempDir);
	}

	private FileSource write(String name, String text, long time) throws IOException {
		FileSource f = TestFiles.write(dir.getChild(name), text);
		f.setLastModified(time);
		return f;
	}

	private static PropertiesDomainList initialized(FileSource f, String key) throws IOException {
		Map<String, String> s = new HashMap<String, String>();
		s.put(PropertiesDomainList.FILE, TestFiles.setting(f));
		if( key != null ) {
			s.put(PropertiesDomainList.KEY, key);
		}
		PropertiesDomainList l = new PropertiesDomainList();
		l.initialize(s::get);
		return l;
	}

	@ParameterizedTest
	@ValueSource(strings = { TestFiles.LOCAL, TestFiles.MEMORY })
	public void readsTheDomainsSetting(String type) throws IOException {
		on(type);
		FileSource f = write("queue.properties", "host=mx1.example.net\ndomains=Example.COM, mxtest.example.org.  other.test\n", 1_000_000);
		PropertiesDomainList l = initialized(f, null);
		assertEquals(new TreeSet<String>(Arrays.asList("example.com", "mxtest.example.org", "other.test")), l.getDomains());
		assertTrue(l.contains("EXAMPLE.com."));
		assertFalse(l.contains("www.example.com"), "exactly the domain, not names below it");
		assertTrue(l.getErrors().isEmpty());
	}

	@ParameterizedTest
	@ValueSource(strings = { TestFiles.LOCAL, TestFiles.MEMORY })
	public void anotherKeyAndBadNames(String type) throws IOException {
		on(type);
		FileSource f = write("dns.properties", "zones=a.test bad..name noDot ok.test\n", 1_000_000);
		PropertiesDomainList l = initialized(f, "zones");
		assertEquals(new TreeSet<String>(Arrays.asList("a.test", "ok.test")), l.getDomains());
		assertEquals(2, l.getErrors().size(), l.getErrors().toString());
	}

	@ParameterizedTest
	@ValueSource(strings = { TestFiles.LOCAL, TestFiles.MEMORY })
	public void reloadIfChanged(String type) throws IOException {
		on(type);
		FileSource f = write("queue.properties", "domains=a.test\n", 1_000_000);
		PropertiesDomainList l = new PropertiesDomainList(f, null);
		assertFalse(l.reloadIfChanged(), "nothing changed");
		write("queue.properties", "domains=a.test b.test\n", 2_000_000);
		assertTrue(l.reloadIfChanged());
		assertTrue(l.contains("b.test"));
		write("queue.properties", "host=x\ndomains=a.test b.test\n", 3_000_000);
		assertFalse(l.reloadIfChanged(), "the file changed, the domains didn't");
	}

	@ParameterizedTest
	@ValueSource(strings = { TestFiles.LOCAL, TestFiles.MEMORY })
	public void anUnreadableFileKeepsTheList(String type) throws IOException {
		on(type);
		FileSource f = write("queue.properties", "domains=a.test\n", 1_000_000);
		PropertiesDomainList l = new PropertiesDomainList(f, null);
		assertTrue(f.delete());
		assertThrows(DomainListUnavailableException.class, l::reloadIfChanged);
		assertTrue(l.contains("a.test"), "the list read last is kept");
	}

	@Test
	public void theFileMustBeSet() throws IOException {
		on(TestFiles.LOCAL);
		PropertiesDomainList l = new PropertiesDomainList();
		assertThrows(IOException.class, () -> l.initialize(k -> null));
		assertThrows(DomainListUnavailableException.class, () -> initialized(dir.getChild("missing"), null));
	}
}
