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
 * @param <S> the protocol's session state enum
 */
public interface IStatefulCommand<S extends Enum<S>> extends ICommand {

	/**
	 * @return the states this command may run in. null or empty means every state.
	 */
	Set<S> getValidStates();
}
