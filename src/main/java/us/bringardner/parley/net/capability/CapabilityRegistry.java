package us.bringardner.parley.net.capability;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import us.bringardner.parley.net.server.ICommandProcessor;

/**
 * What a server can offer, with the conditions that decide whether it is offered to a given
 * session. Protocols make this decision by hand today: STLS only before TLS, SASL mechanisms
 * only after TLS, MLST only when the file system supports it, and so on.
 * <pre>
 *   registry.add("PIPELINING")
 *           .addWhen(p -&gt; !p.isTls() &amp;&amp; tlsAvailable, "STARTTLS")
 *           .addDynamic("AUTH", p -&gt; mechanisms.offered(auth, p.isTls()));
 *   ...
 *   reply lines = registry.resolve(processor).toLines();
 * </pre>
 * Register the entries once when the server is set up; {@link #resolve} is called for every
 * EHLO / CAPA / FEAT / CAPABILITY. Not thread safe for registering.
 */
public class CapabilityRegistry {

	private static final class Entry {
		final String name;
		final Function<ICommandProcessor, List<String>> params;

		Entry(String name, Function<ICommandProcessor, List<String>> params) {
			this.name = name;
			this.params = params;
		}
	}

	private final List<Entry> entries = new ArrayList<>();

	/** Always offer the capability. */
	public CapabilityRegistry add(String name, String... params) {
		final List<String> fixed = Arrays.asList(params.clone());
		entries.add(new Entry(name, p -> fixed));
		return this;
	}

	/** Offer the capability while the condition holds for the session. */
	public CapabilityRegistry addWhen(Predicate<ICommandProcessor> condition, String name, String... params) {
		final List<String> fixed = Arrays.asList(params.clone());
		entries.add(new Entry(name, p -> condition.test(p) ? fixed : null));
		return this;
	}

	/**
	 * Offer the capability with parameters computed for the session. The capability is left
	 * out when the function returns null (an empty list offers it with no parameters).
	 */
	public CapabilityRegistry addDynamic(String name, Function<ICommandProcessor, List<String>> params) {
		entries.add(new Entry(name, params));
		return this;
	}

	/**
	 * Like {@link #addDynamic} but the capability is left out when the parameters come back
	 * empty, e.g. "AUTH" with no mechanism to offer.
	 */
	public CapabilityRegistry addDynamicRequireParams(String name, Function<ICommandProcessor, List<String>> params) {
		entries.add(new Entry(name, p -> {
			List<String> ret = params.apply(p);
			return ret == null || ret.isEmpty() ? null : ret;
		}));
		return this;
	}

	/**
	 * @param processor the session the capabilities are for, passed to the conditions
	 * @return the capabilities to offer this session, in registration order
	 */
	public CapabilitySet resolve(ICommandProcessor processor) {
		CapabilitySet ret = new CapabilitySet();
		for (Entry e : entries) {
			List<String> params = e.params.apply(processor);
			if (params != null) {
				ret.add(e.name, params.toArray(new String[0]));
			}
		}
		return ret;
	}
}
