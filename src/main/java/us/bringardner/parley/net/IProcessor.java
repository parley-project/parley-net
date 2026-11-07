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
package us.bringardner.parley.net;


import java.util.Map;

import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.net.server.ILoginSession;
import us.bringardner.parley.net.server.IServer;






/**
 * Objects that implement this Interface know how
 * to process client connections accepted by a server.
 * 
 * 
 * @author: Tony Bringardner
 */
public interface IProcessor extends IManagedThread, ILoginSession {
	
	/**
	 * Set the Server that accepted this connection.
	 * 
	 * @param server
	 */
	public void setServer(IServer server);
	
	/**
	 * @return The Server that accepted this connection.
	 */
	public IServer getServer();

	/**
	 *  Process an incoming connection.
	 *  
	 * @param connection
	 */
	public void setConnection(IConnection connection);
	
	/**
	 * @return the current connection
	 */
	public IConnection getConnection();
	
	
	public Map<String,Object> getSessionValues() ;
	public void setSessionValue(String name, Object value) ;
	public Object getSessionValue(String name) ;
	public Object removeSessionValue(String name);
	
	public Object removeServerRuntimeValue(String name) ;
	public Map<String,Object> getServerRuntimeValues() ;
	public void setServerRuntimeValue(String name, Object value) ;
	public Object getServerRuntimeValue(String name);

	/**
	 * The server is about to close this session on its own: it has been idle too long, nobody
	 * logged in in time, or the server is stopping. A protocol overrides this to say goodbye in
	 * its own way (FTP and SMTP: 421). The default sends nothing, which is what POP3 does (RFC 1939).
	 * <p>
	 * It is called on a thread of its own, and the connection is closed after it returns or after
	 * {@link us.bringardner.parley.net.server.Server#GOODBYE_WAIT_MS} ms, whichever is first, so a
	 * client that doesn't read can't hold the server up.
	 *
	 * @param reason why the session is being closed
	 * @since 2.0.0
	 */
	public default void replyClosing(us.bringardner.parley.net.server.CloseReason reason) throws java.io.IOException {
	}

	/** Asks the server ({@link IServer#checkPermission}) with {@link #getRequester()}. */
	@Override
	public default AuthorizationResult checkPermission(ParleyPermission needed, ProtectedResource resource) {
		return getServer().checkPermission(getRequester(), needed, resource);
	}
	
	
}