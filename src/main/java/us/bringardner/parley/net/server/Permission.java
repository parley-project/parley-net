package us.bringardner.parley.net.server;

/**
 * <PRE>
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
 */
public class Permission implements IPermission {

	String name;
	
	public Permission(String name) {
		this.name = name;
	}
	
	@Override
	public String getName() {
		return name;
	}
	
	@Override
	public int hashCode() {
		return name.hashCode();
	}
	
	@Override
	public String toString() {
		return name;
	}
	
	@Override
	public boolean equals(Object obj) {
		boolean ret = false;
		if (obj instanceof IPermission) {
			 ret = ((IPermission) obj).getName().equals(getName());			
		}
		
		return ret;
	}

}
