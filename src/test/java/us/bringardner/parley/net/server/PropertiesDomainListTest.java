package us.bringardner.parley.net.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class PropertiesDomainListTest {

	@TempDir
	Path dir;

	private File write(String name, String text, long time) throws IOException {
		File f = dir.resolve(name).toFile();
		Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
		f.setLastModified(time);
		return f;
	}

	private static PropertiesDomainList initialized(File f, String key) throws IOException {
		Map<String, String> s = new HashMap<String, String>();
		s.put(PropertiesDomainList.FILE, f.getPath());
		if( key != null ) {
			s.put(PropertiesDomainList.KEY, key);
		}
		PropertiesDomainList l = new PropertiesDomainList();
		l.initialize(s::get);
		return l;
	}

	@Test
	public void readsTheDomainsSetting() throws IOException {
		File f = write("queue.properties", "host=mx1.example.net\ndomains=Example.COM, mxtest.example.org.  other.test\n", 1_000_000);
		PropertiesDomainList l = initialized(f, null);
		assertEquals(new TreeSet<String>(Arrays.asList("example.com", "mxtest.example.org", "other.test")), l.getDomains());
		assertTrue(l.contains("EXAMPLE.com."));
		assertFalse(l.contains("www.example.com"), "exactly the domain, not names below it");
		assertTrue(l.getErrors().isEmpty());
	}

	@Test
	public void anotherKeyAndBadNames() throws IOException {
		File f = write("dns.properties", "zones=a.test bad..name noDot ok.test\n", 1_000_000);
		PropertiesDomainList l = initialized(f, "zones");
		assertEquals(new TreeSet<String>(Arrays.asList("a.test", "ok.test")), l.getDomains());
		assertEquals(2, l.getErrors().size(), l.getErrors().toString());
	}

	@Test
	public void reloadIfChanged() throws IOException {
		File f = write("queue.properties", "domains=a.test\n", 1_000_000);
		PropertiesDomainList l = new PropertiesDomainList(f, null);
		assertFalse(l.reloadIfChanged(), "nothing changed");
		write("queue.properties", "domains=a.test b.test\n", 2_000_000);
		assertTrue(l.reloadIfChanged());
		assertTrue(l.contains("b.test"));
		write("queue.properties", "host=x\ndomains=a.test b.test\n", 3_000_000);
		assertFalse(l.reloadIfChanged(), "the file changed, the domains didn't");
	}

	@Test
	public void anUnreadableFileKeepsTheList() throws IOException {
		File f = write("queue.properties", "domains=a.test\n", 1_000_000);
		PropertiesDomainList l = new PropertiesDomainList(f, null);
		assertTrue(f.delete());
		assertThrows(DomainListUnavailableException.class, l::reloadIfChanged);
		assertTrue(l.contains("a.test"), "the list read last is kept");
	}

	@Test
	public void theFileMustBeSet() {
		PropertiesDomainList l = new PropertiesDomainList();
		assertThrows(IOException.class, () -> l.initialize(k -> null));
		assertThrows(DomainListUnavailableException.class, () -> initialized(dir.resolve("missing").toFile(), null));
	}
}
