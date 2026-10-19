/**
 * The service-provider interface for keeping locks between servers: implement
 * {@link us.bringardner.parley.net.lock.spi.LockProvider} (and the
 * {@link us.bringardner.parley.net.lock.spi.LockService} it opens) to give
 * {@link us.bringardner.parley.net.lock.Locks} another way, such as a lock server. Parley's own,
 * {@code region} and {@code lease}, implement it too.
 * @since 1.1.0
 */
package us.bringardner.parley.net.lock.spi;
