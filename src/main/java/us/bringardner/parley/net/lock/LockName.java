package us.bringardner.parley.net.lock;

import java.util.Objects;

/**
 * A name in a lock domain, for {@link Locks#lockAll}: ordered by domain, then name, so locks across
 * several stores are always taken in one order.
 * @since 1.1.0
 */
public final class LockName implements Comparable<LockName> {

	private final LockDomain domain;
	private final String name;

	LockName(LockDomain domain, String name) {
		this.domain = Objects.requireNonNull(domain, "domain");
		this.name = Objects.requireNonNull(name, "name");
	}

	/** @return the domain */
	public LockDomain domain() {
		return domain;
	}

	/** @return the name within it */
	public String name() {
		return name;
	}

	@Override
	public int compareTo(LockName o) {
		int c = domain.name().compareTo(o.domain.name());
		return c != 0 ? c : name.compareTo(o.name);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof LockName && ((LockName) o).domain == domain && ((LockName) o).name.equals(name);
	}

	@Override
	public int hashCode() {
		return domain.name().hashCode() * 31 + name.hashCode();
	}

	@Override
	public String toString() {
		return domain.name() + ":" + name;
	}
}
