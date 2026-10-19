package us.bringardner.parley.net.lock;

import java.util.Collections;
import java.util.List;

/**
 * The holdings {@link LockSpace#lockAll} took; closing the group closes them all, last first.
 * @since 1.1.0
 */
public final class LockGroup implements AutoCloseable {

	private final List<NamedLock> locks;

	LockGroup(List<NamedLock> locks) {
		this.locks = Collections.unmodifiableList(locks);
	}

	/** @return the holdings, in the order they were taken */
	public List<NamedLock> locks() {
		return locks;
	}

	@Override
	public void close() {
		for (int i = locks.size() - 1; i >= 0; i--) {
			locks.get(i).close();
		}
	}
}
