/**
 * Locks for servers: locks on names (a mailbox, a maildrop, a queue entry) that reach the threads
 * of this JVM and the other servers using the same stores.
 * <ul>
 * <li>{@link us.bringardner.parley.net.lock.Locks}: one per JVM; each store is registered as a
 * {@link us.bringardner.parley.net.lock.LockDomain}, with {@link us.bringardner.parley.net.lock.LockOptions}
 * (how many servers share it: {@link us.bringardner.parley.net.lock.Sharing}; which provider).</li>
 * <li>{@link us.bringardner.parley.net.lock.NamedLock}: one holding of a name; reentrant by
 * default, with timeouts, threads served first come first served.</li>
 * <li>{@link us.bringardner.parley.net.lock.StoreClaim}: a server's claim on a store, alone or
 * shared.</li>
 * <li>{@link us.bringardner.parley.net.lock.AtomicWrite}: replacing a shared file under its lock.</li>
 * <li>Providers keep locks between servers: Parley's liberal {@code region} locks (the store's
 * own, through parley-files) and conservative {@code lease} directories, chosen from the store's
 * capabilities, or another through {@link us.bringardner.parley.net.lock.spi}.</li>
 * </ul>
 * @since 1.1.0
 */
package us.bringardner.parley.net.lock;
