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

import java.io.IOException;
import java.util.Set;
import java.util.function.Function;

/**
 * A list of domain names, kept wherever a deployment keeps it: the mail domains a mail server
 * accepts mail for, the domains a DNS server answers for. One list can serve several servers, so
 * it is changed in one place and each server reads it again.
 * <p>
 * A server makes its list from a class name (a public constructor with no arguments), calls
 * {@link #initialize(Function)} once, and then {@link #reloadIfChanged()} whenever it wants to
 * see changes (e.g. before answering, or on a timer). Like {@link IAccessControlList}, a list
 * that can't be read throws {@link DomainListUnavailableException}; the server keeps what it had.
 * <p>
 * Names are lower case, without a trailing dot. The list holds names only: what a server does
 * with a domain is up to the server.
 *
 * @since 2.0.0
 */
public interface IDomainList {

	/**
	 * Prepare the list and read it the first time.
	 *
	 * @param setting the deployment's settings for this list, by name (e.g. "file"), as the server
	 *  that uses it keeps them (a DNS server's parley.dns.domainList.file, say); null if not set
	 * @throws IOException if a setting is missing or wrong
	 * @throws DomainListUnavailableException if the list can't be read
	 */
	void initialize(Function<String, String> setting) throws IOException;

	/** @return true if the list holds exactly this domain (any case, with or without a trailing dot) */
	boolean contains(String domain) throws DomainListUnavailableException;

	/** @return the domains (lower case, no trailing dot), sorted; a snapshot that doesn't change */
	Set<String> getDomains() throws DomainListUnavailableException;

	/** Read the list again now. */
	void reload() throws DomainListUnavailableException;

	/**
	 * Read the list again if where it is kept changed (a cheap check, fine to call often).
	 * @return true if the domains changed
	 */
	boolean reloadIfChanged() throws DomainListUnavailableException;
}
