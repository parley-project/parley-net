package us.bringardner.parley.net.server;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * The state of one protocol session, for the many protocols whose commands are legal only in
 * some states (SMTP's MAIL / RCPT / DATA sequence, POP3's AUTHORIZATION / TRANSACTION /
 * UPDATE, IMAP's not authenticated / authenticated / selected, FTP's USER then PASS).
 * <p>
 * The protocol defines its states as an enum. A command declares where it is valid with
 * {@link IStatefulCommand} and moves the session on with {@link #moveTo(Enum)}. By default any
 * move is allowed; call {@link #allow(Enum, Enum...)} to list the legal moves, after which any
 * other move throws.
 * <p>
 * One instance belongs to one session; it is safe to read from another thread.
 *
 * @param <S> the state enum
 */
public final class StateMachine<S extends Enum<S>> {

	private final Class<S> type;
	private final Map<S, Set<S>> allowed;
	private volatile S state;
	private boolean restricted;

	/** @param initial the state a new session starts in */
	public StateMachine(S initial) {
		if (initial == null) {
			throw new IllegalArgumentException("initial state is required");
		}
		this.type = initial.getDeclaringClass();
		this.allowed = new EnumMap<>(type);
		this.state = initial;
	}

	/**
	 * Declare which states may follow {@code from}. After the first call only declared moves
	 * are legal (moving to the current state is always legal).
	 *
	 * @return this, for chaining
	 */
	@SafeVarargs
	public final synchronized StateMachine<S> allow(S from, S... to) {
		restricted = true;
		Set<S> set = allowed.get(from);
		if (set == null) {
			set = EnumSet.noneOf(type);
			allowed.put(from, set);
		}
		set.addAll(Arrays.asList(to));
		return this;
	}

	/** @return the current state */
	public S get() {
		return state;
	}

	/** @return true if the current state is one of the given states */
	@SafeVarargs
	public final boolean is(S... states) {
		S current = state;
		for (S s : states) {
			if (s == current) {
				return true;
			}
		}
		return false;
	}

	/** @return true if {@link #moveTo(Enum)} would accept the move */
	public synchronized boolean canMoveTo(S to) {
		if (to == null) {
			return false;
		}
		if (!restricted || to == state) {
			return true;
		}
		Set<S> set = allowed.get(state);
		return set != null && set.contains(to);
	}

	/**
	 * Move to a new state.
	 *
	 * @throws IllegalStateException if moves are restricted and this one isn't declared
	 */
	public synchronized void moveTo(S to) {
		if (!canMoveTo(to)) {
			throw new IllegalStateException("Can't move from " + state + " to " + to);
		}
		state = to;
	}

	/**
	 * @return true if the command may run in the current state; commands that declare no
	 *         states are valid in every state
	 */
	public boolean isValid(IStatefulCommand<?> command) {
		Set<?> valid = command.getValidStates();
		return valid == null || valid.isEmpty() || valid.contains(state);
	}

	@Override
	public String toString() {
		return "StateMachine[" + state + "]";
	}
}
