package us.bringardner.parley.net.server;

import java.util.Set;

/**
 * A command that is legal only in some states of the session, such as SMTP's RCPT (after MAIL,
 * before DATA), POP3's RETR (TRANSACTION) or IMAP's FETCH (a mailbox is selected).
 * <p>
 * {@link AbstractCommandProcessor} checks this before it runs the command, when the processor
 * supplies a {@link StateMachine} (see {@link AbstractCommandProcessor#getStateMachine()}).
 * A command that doesn't implement this interface is valid in every state.
 *
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
 *
 * @param <S> the protocol's session state enum
 */
public interface IStatefulCommand<S extends Enum<S>> extends ICommand {

	/**
	 * @return the states this command may run in. null or empty means every state.
	 */
	Set<S> getValidStates();
}
