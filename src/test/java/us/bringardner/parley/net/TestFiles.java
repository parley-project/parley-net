package us.bringardner.parley.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/**
 * FileSources for tests (To-Do 18.8 C6): a JUnit {@code @TempDir} on the local file system, or a
 * folder of a new memory file system, so a test can run on both.
 */
public final class TestFiles {

	/** The local file system (a FileProxy for the @TempDir) */
	public static final String LOCAL = "local";
	/** A new memory file system */
	public static final String MEMORY = "memory";

	private TestFiles() {
	}

	/** The @TempDir as a FileSource on the local file system */
	public static FileSource local(Path tempDir) throws IOException {
		return FileSourceFactory.fileProxyFactory.createFileSource(tempDir.toAbsolutePath().toString());
	}

	/** A new, empty folder: the @TempDir (LOCAL), or a folder of a new memory file system (MEMORY) */
	public static FileSource folder(String type, Path tempDir) throws IOException {
		if (LOCAL.equals(type)) {
			return local(tempDir);
		}
		FileSourceFactory memory = new MemoryFileSourceFactory();
		memory.connect();
		FileSource ret = memory.createFileSource("/test" + System.nanoTime());
		if (!ret.mkdirs()) {
			throw new IOException("Can't make " + ret);
		}
		return ret;
	}

	/**
	 * What a setting holds to name F: its path for a local file, else its {@code filesource:} URL
	 * (with the memory file system's session, so it is the same one)
	 */
	public static String setting(FileSource f) throws IOException {
		return f.getFileSourceFactory() == FileSourceFactory.fileProxyFactory ? f.getPath() : f.toURL().toString();
	}

	/** Write TEXT (UTF-8) to F */
	public static FileSource write(FileSource f, String text) throws IOException {
		try (OutputStream out = f.getOutputStream()) {
			out.write(text.getBytes(StandardCharsets.UTF_8));
		}
		return f;
	}

	/** F's text (UTF-8) */
	public static String read(FileSource f) throws IOException {
		try (InputStream in = f.getInputStream()) {
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}
}
