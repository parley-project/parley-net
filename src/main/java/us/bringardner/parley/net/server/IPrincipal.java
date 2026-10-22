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

import java.util.List;
import java.util.Map;

/**
 * An interface to represent a Principle (a.k.a. a User)
 * All principles are maintained by an AccessControlList. 
 */
public interface IPrincipal {

	enum State {Unvalidated,Authenticated,Declined};
	
	boolean authenticate(byte [] credentials);
	
	State getState();
	void setState(State state);
	
	// credentials 
	byte [] getCredentials ();
	void setCredentials(byte [] credentials);
	
	void add(IPermission permission) ;
	boolean hasPermission(IPermission permision) ;
	boolean remove(IPermission permission) ;
	/**
	 * @return a copy of this principal's permissions
	 */
	List<IPermission> getPermissions();
	void setPermissions(List<IPermission> permissions) ;

	
	Object getParameter(Object key) ;
	Object removeParameter(Object key);
	void setParameter(Object key, Object value);
	Map<Object,Object> getParameters();
	void setParameters(Map<Object,Object> parameters) ;
	
	String getName();

}
