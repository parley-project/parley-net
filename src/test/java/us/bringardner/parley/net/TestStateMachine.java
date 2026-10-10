package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.ServerTestSupport.TestServer;
import us.bringardner.parley.net.client.CommandClient;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.net.server.IStatefulCommand;
import us.bringardner.parley.net.server.Permission;
import us.bringardner.parley.net.server.StateMachine;

/**
 * Session states: the machine itself, and a processor that refuses commands in the wrong state.
 */
public class TestStateMachine {

	/** A tiny SMTP-like dialog. */
	enum Phase {
		GREETED, MAIL, DATA
	}

	@Test
	public void startsInTheInitialState() {
		StateMachine<Phase> sm = new StateMachine<>(Phase.GREETED);
		assertEquals(Phase.GREETED, sm.get());
		assertTrue(sm.is(Phase.GREETED));
		assertTrue(sm.is(Phase.MAIL, Phase.GREETED));
		assertFalse(sm.is(Phase.DATA));
	}

	@Test
	public void anyMoveIsLegalUnlessRestricted() {
		StateMachine<Phase> sm = new StateMachine<>(Phase.GREETED);
		sm.moveTo(Phase.DATA);
		assertEquals(Phase.DATA, sm.get());
	}

	@Test
	public void restrictedMovesAreEnforced() {
		StateMachine<Phase> sm = new StateMachine<>(Phase.GREETED)
				.allow(Phase.GREETED, Phase.MAIL)
				.allow(Phase.MAIL, Phase.DATA, Phase.GREETED);
		assertFalse(sm.canMoveTo(Phase.DATA));
		assertThrows(IllegalStateException.class, () -> sm.moveTo(Phase.DATA));
		assertEquals(Phase.GREETED, sm.get(), "a refused move leaves the state alone");
		sm.moveTo(Phase.MAIL);
		sm.moveTo(Phase.DATA);
		assertThrows(IllegalStateException.class, () -> sm.moveTo(Phase.MAIL), "DATA has no way out declared");
		sm.moveTo(Phase.DATA); // staying is always fine
	}

	@Test
	public void commandValidity() {
		StateMachine<Phase> sm = new StateMachine<>(Phase.MAIL);
		assertTrue(sm.isValid(cmd("ANY", null)));
		assertTrue(sm.isValid(cmd("EMPTY", EnumSet.noneOf(Phase.class))));
		assertTrue(sm.isValid(cmd("RCPT", EnumSet.of(Phase.MAIL))));
		assertFalse(sm.isValid(cmd("MAIL", EnumSet.of(Phase.GREETED))));
	}

	private static IStatefulCommand<Phase> cmd(String name, Set<Phase> valid) {
		return new IStatefulCommand<Phase>() {
			private static final long serialVersionUID = 1L;

			@Override
			public String getName() {
				return name;
			}

			@Override
			public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
			}

			@Override
			public IPermission getPermission() {
				return new Permission(name);
			}

			@Override
			public boolean requiresAuthorization() {
				return false;
			}

			@Override
			public Set<Phase> getValidStates() {
				return valid;
			}
		};
	}

	// --------------------------------------------------------------- over a connection

	private static TestServer svr;

	@BeforeAll
	public static void startServer() {
		Map<String, ICommand> commands = new HashMap<>();
		commands.put("MAIL", new Move("MAIL", EnumSet.of(Phase.GREETED), Phase.MAIL));
		commands.put("DATA", new Move("DATA", EnumSet.of(Phase.MAIL), Phase.DATA));
		commands.put("RSET", new Move("RSET", null, Phase.GREETED));
		commands.put("NOOP", ServerTestSupport.command("NOOP", false, 
				(p, c) -> p.reply(ICommandProcessor.REPLY_200_GENERIC_OK, "ok")));
		svr = ServerTestSupport.create("StateServer", commands, null);
		svr.setProcessorFactory(() -> new AbstractCommandProcessor() {
			private static final long serialVersionUID = 1L;
			private final StateMachine<Phase> states = new StateMachine<>(Phase.GREETED);

			@Override
			public String translateResponseCode(int code) {
				return "" + code;
			}

			@Override
			public ICommandFactory getCommandFactory() {
				return context -> {
					String name = context.getFirstToken();
					return name == null ? null : commands.get(name);
				};
			}

			@Override
			protected StateMachine<?> getStateMachine() {
				return states;
			}

			@Override
			protected void replyInvalidState(ICommand command, StateMachine<?> sm) throws IOException {
				reply("503 bad sequence of commands");
			}

			{
				setSessionValue("states", states);
			}
		});
		ServerTestSupport.start(svr);
	}

	@AfterAll
	public static void stopServer() {
		ServerTestSupport.stop(svr);
	}

	/** Valid in some states; on success moves the session. */
	static class Move extends ServerTestSupport_Base implements IStatefulCommand<Phase> {
		private static final long serialVersionUID = 1L;
		private final Set<Phase> valid;
		private final Phase to;

		Move(String name, Set<Phase> valid, Phase to) {
			super(name);
			this.valid = valid;
			this.to = to;
		}

		@Override
		@SuppressWarnings("unchecked")
		public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
			((StateMachine<Phase>) processor.getSessionValue("states")).moveTo(to);
			processor.reply(REPLY_200_GENERIC_OK, name + " ok");
		}

		@Override
		public Set<Phase> getValidStates() {
			return valid;
		}
	}

	/** Name, no authorization, for the Move test commands. */
	abstract static class ServerTestSupport_Base implements ICommand {
		private static final long serialVersionUID = 1L;
		final String name;

		ServerTestSupport_Base(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public IPermission getPermission() {
			return new Permission(name);
		}

		@Override
		public boolean requiresAuthorization() {
			return false;
		}
	}

	@Test
	public void commandsAreRefusedOutsideTheirStates() throws Exception {
		try (CommandClient client = ServerTestSupport.connect(svr)) {
			assertEquals(503, client.executeCommand("DATA").getResponseCode(), "DATA before MAIL");
			assertTrue(client.executeCommand("MAIL").isPositive());
			assertEquals(503, client.executeCommand("MAIL").getResponseCode(), "MAIL twice");
			assertTrue(client.executeCommand("DATA").isPositive());
			assertTrue(client.executeCommand("NOOP").isPositive(), "commands with no states run anywhere");
			assertTrue(client.executeCommand("RSET").isPositive(), "RSET declares no states");
			assertTrue(client.executeCommand("MAIL").isPositive(), "back at the start");
		}
	}
}
