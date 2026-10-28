/**
 * <PRE>
 * 
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
 *   
 *   
 *	@author Tony Bringardner   
 *
 *
 */
package us.bringardner.parley.net.server;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * A domain list kept in a properties file, as one setting that lists the domains separated by
 * commas or spaces: by default the {@code domains} setting of the mail queue's
 * {@code queue.properties}, so mail and DNS share one list.
 * <p>
 * Settings: {@code file} (required), the properties file; {@code key} (default {@code domains}),
 * the setting in it. A name that isn't a domain name is left out and reported by
 * {@link #getErrors()}. The file is read again when its time or size changes; if it can't be
 * read, the list read last is kept.
 *
 * @since 2.0.0
 */
public class PropertiesDomainList implements IDomainList {

	/** The setting naming the properties file. */
	public static final String FILE = "file";
	/** The setting naming the key in the file (default {@value #DEFAULT_KEY}). */
	public static final String KEY = "key";
	public static final String DEFAULT_KEY = "domains";

	private static final Pattern DOMAIN = Pattern.compile("[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+");

	private File file;
	private String key = DEFAULT_KEY;
	private volatile Set<String> domains = Collections.emptySet();
	private volatile List<String> errors = Collections.emptyList();
	//  the file's time and size when it was read last; null before the first read
	private volatile String stamp;

	public PropertiesDomainList() {
	}

	/** A list read from this file's setting (initialized: no need to call initialize). */
	public PropertiesDomainList(File file, String key) throws DomainListUnavailableException {
		this.file = file;
		this.key = key == null ? DEFAULT_KEY : key;
		reload();
	}

	@Override
	public void initialize(Function<String, String> setting) throws IOException {
		String f = setting.apply(FILE);
		if( f == null || f.trim().isEmpty() ) {
			throw new IOException(getClass().getSimpleName()+": the setting '"+FILE+"' (the properties file) is not set");
		}
		String k = setting.apply(KEY);
		file = new File(f.trim());
		key = k == null || k.trim().isEmpty() ? DEFAULT_KEY : k.trim();
		reload();
	}

	/** The properties file. */
	public File getFile() {
		return file;
	}

	/** The setting in the file that lists the domains. */
	public String getKey() {
		return key;
	}

	/** What was wrong in the last read (names left out); empty if nothing. */
	public List<String> getErrors() {
		return errors;
	}

	@Override
	public boolean contains(String domain) {
		return domain != null && domains.contains(normalize(domain));
	}

	@Override
	public Set<String> getDomains() {
		return domains;
	}

	@Override
	public void reload() throws DomainListUnavailableException {
		read();
	}

	@Override
	public boolean reloadIfChanged() throws DomainListUnavailableException {
		if( stamp(file).equals(stamp) ) {
			return false;
		}
		return read();
	}

	/** @return true if the domains changed */
	private synchronized boolean read() throws DomainListUnavailableException {
		if( file == null ) {
			throw new DomainListUnavailableException(getClass().getSimpleName()+" is not initialized");
		}
		String s = stamp(file);
		Properties p = new Properties();
		try(InputStream in = Files.newInputStream(file.toPath())) {
			p.load(in);
		} catch(IOException | RuntimeException e) {
			throw new DomainListUnavailableException("Can't read the domain list from "+file+": "+e.getMessage(), e);
		}
		Set<String> d = new TreeSet<String>();
		List<String> errs = new ArrayList<String>();
		String value = p.getProperty(key);
		if( value != null ) {
			for(String n : value.split("[,\\s]+")) {
				if( n.isEmpty() ) {
					continue;
				}
				String norm = normalize(n);
				if( DOMAIN.matcher(norm).matches() ) {
					d.add(norm);
				} else {
					errs.add(file+": "+key+": not a domain name: "+n);
				}
			}
		}
		boolean changed = !d.equals(domains);
		domains = Collections.unmodifiableSet(d);
		errors = Collections.unmodifiableList(errs);
		stamp = s;
		return changed;
	}

	private static String stamp(File f) {
		return f != null && f.exists() ? f.lastModified()+"/"+f.length() : "-";
	}

	private static String normalize(String n) {
		String s = n.trim().toLowerCase(Locale.ROOT);
		return s.endsWith(".") ? s.substring(0, s.length()-1) : s;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName()+"("+file+" "+key+")";
	}
}
