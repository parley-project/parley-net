package us.bringardner.parley.net.lock;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.Syncable;

/**
 * Replace a shared file while holding the lock that guards it, so a server that lost its lock
 * writes nothing and a reader never sees a half-written file:
 * <ol>
 * <li>the new content goes to a temporary file in the same directory, with a name no other writer
 * uses ({@code .<name>.<random>.tmp});</li>
 * <li>it is made durable where the store can ({@link Syncable});</li>
 * <li>the lock is checked ({@link NamedLock#checkValid()}): lost, the temporary file is deleted and
 * {@link LockLostException} thrown;</li>
 * <li>the temporary file is renamed over the target ({@link FileSource#renameTo(FileSource, boolean)}):
 * in one step where the store's replace is atomic
 * ({@link us.bringardner.parley.files.FileSourceCapabilities#atomicReplace()}); elsewhere the target
 * is deleted first, so for that moment it is missing, which readers there must allow.</li>
 * </ol>
 * @since 1.1.0
 */
public final class AtomicWrite {

	private static final Logger LOG = Logger.getLogger(AtomicWrite.class.getName());

	private AtomicWrite() {
	}

	/** What writes the new content. */
	@FunctionalInterface
	public interface Writer {
		/**
		 * @param out where the content goes; closed by AtomicWrite
		 * @throws IOException as writing does
		 */
		void write(OutputStream out) throws IOException;
	}

	/**
	 * Replace (or create) a file.
	 * @param target the file
	 * @param lock the lock that guards it, held by this thread
	 * @param writer writes the new content
	 * @throws LockLostException if the lock was lost before the content went in: nothing changed
	 * @throws IOException if writing or renaming fails
	 */
	public static void replace(FileSource target, NamedLock lock, Writer writer) throws IOException {
		Objects.requireNonNull(target, "target");
		Objects.requireNonNull(lock, "lock");
		Objects.requireNonNull(writer, "writer");
		FileSource dir = target.getParentFile();
		if( dir == null ) {
			throw new IOException("Can't replace " + target.getAbsolutePath() + ": it has no directory");
		}
		FileSource tmp = dir.getChild("." + target.getName() + "." + UUID.randomUUID().toString().replace("-", "") + ".tmp");
		boolean done = false;
		try {
			try (OutputStream out = tmp.getOutputStream()) {
				writer.write(out);
				if( out instanceof Syncable ) {
					((Syncable) out).sync();
				} else {
					out.flush();
				}
			}
			lock.checkValid();
			if( !tmp.renameTo(target, true) ) {
				throw new IOException("Can't replace " + target.getAbsolutePath() + " with " + tmp.getAbsolutePath());
			}
			done = true;
		} finally {
			if( !done ) {
				try {
					if( tmp.exists() ) {
						tmp.delete();
					}
				} catch (IOException | RuntimeException e) {
					LOG.log(Level.WARNING, "Removing " + tmp.getAbsolutePath(), e);
				}
			}
		}
	}
}
