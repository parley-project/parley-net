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
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link FileUserRegistry} whose users come from settings instead of a file: with the
 * server's property prefix, {@code prefix.user0}, {@code prefix.user1} ... are read until
 * one is missing. Each value is a line in the user file's format:
 * <pre>
 * tony , password , perm1|perm2 , key=val|key=val
 * </pre>
 * The users are read once; settings changed later are not read again.
 */
public class PropertiesUserRegistry extends FileUserRegistry {

	public static final String USER_PROPERTY = "user";

	/** A registry with no users, until {@link #initialize(String)} reads some. */
	public PropertiesUserRegistry() {
		super();
	}

	/**
	 * A registry for a server: it reads the server's settings and the users under the server's
	 * property prefix. The server uses this constructor when its
	 * {@value IBaseServer#AUTHENTICATION_PROVIDER_PROPERTY} setting names this class.
	 *
	 * @param server the server that uses the registry
	 * @since 2.0.0
	 */
	public PropertiesUserRegistry(IBaseServer server) {
		super();
		useConfigurationOfServer(server);
		readUsers(server.getPropertyPrefix());
	}

	/**
	 * Read the users from {@code name.user0}, {@code name.user1} ...
	 *
	 * @param name the property prefix; null or empty keeps the current one
	 */
	@Override
	public void initialize(String name) throws IOException {
		readUsers(name);
	}

	private void readUsers(String name) {
		if( name != null && !name.isEmpty()) {
			setPropertyPrefix(name);
		}

		List<String> lines = new ArrayList<String>();
		int idx = 0;
		String tmp = getProperty(propertyName(USER_PROPERTY+idx));
		while( tmp != null ) {
			lines.add(tmp);
			tmp = getProperty(propertyName(USER_PROPERTY+(++idx)));
		}
		load(lines);

		logInfo("PropertiesUserRegistry read "+idx+" users");
	}
}
