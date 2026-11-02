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

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The identity of a user (a principal): its name, the permissions and groups the access
 * control list gives it, and its parameters. It holds no credentials: checking a password,
 * an APOP digest or SCRAM credentials is the job of the {@link IAccessControlList} that
 * made the principal, so a secret never leaves the list.
 * <p>
 * The state is the session's view: a principal a server hands to a session after a login
 * is {@link State#Authenticated}.
 */
public interface IPrincipal {

	enum State {Unvalidated,Authenticated,Declined};
	
	State getState();
	void setState(State state);
	
	void add(IPermission permission) ;
	/**
	 * True if the principal has the permission. Permission names are compared exactly
	 * (case-sensitively): ADMIN is not admin.
	 */
	boolean hasPermission(IPermission permision) ;
	boolean remove(IPermission permission) ;
	/**
	 * @return a copy of this principal's permissions
	 */
	List<IPermission> getPermissions();
	void setPermissions(List<IPermission> permissions) ;

	/**
	 * The groups the user is in, as the access control list names them. A group used in
	 * mailbox ACLs is named with its domain (sales@bringardner.us) and written
	 * {@code $sales@bringardner.us} in a mailbox's ACL.
	 * <p>
	 * The default has none.
	 *
	 * @return a copy of the group names, never null
	 * @since 2.0.0
	 */
	default List<String> getGroups() {
		return Collections.emptyList();
	}
	
	Object getParameter(Object key) ;
	Object removeParameter(Object key);
	void setParameter(Object key, Object value);
	Map<Object,Object> getParameters();
	void setParameters(Map<Object,Object> parameters) ;
	
	String getName();

}
