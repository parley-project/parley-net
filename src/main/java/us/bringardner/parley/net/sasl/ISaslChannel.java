package us.bringardner.parley.net.sasl;

import java.io.IOException;

/**
 * How a protocol carries SASL data: the part {@link SaslServerDriver} can't know. SMTP sends
 * "334 &lt;base64&gt;", IMAP and POP3 send "+ &lt;base64&gt;"; all of them read the answer as a line.
 *
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
public interface ISaslChannel {

	/**
	 * Send a challenge, as the protocol's continuation reply.
	 *
	 * @param base64 the challenge, Base64 encoded ("" if empty)
	 */
	void sendChallenge(String base64) throws IOException;

	/**
	 * @return the client's response line, or null if the connection was closed
	 */
	String readResponse() throws IOException;
}
