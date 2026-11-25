package us.bringardner.parley.net.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import us.bringardner.parley.core.IncludeResolver;
import us.bringardner.parley.files.FileSource;

/**
 * Finds the settings files (and the files they include) on a file system: a path on the default
 * file system, or a {@code filesource:} URL ({@link FileSource#of(String)}). A name that isn't
 * absolute is found next to the file that includes it.
 * <p>
 * The file is UTF-8 (a file that isn't valid UTF-8 is read as ISO-8859-1, as Properties.load reads
 * it); a leading byte order mark is ignored. It is given to the reader as Properties.load wants
 * it: ISO-8859-1 with \\uXXXX for the characters beyond it.
 * <p>
 * Registered as a service for {@link IncludeResolver}, so {@code BaseObject.readSettingsFile} and
 * {@code parley.include} find files with it when parley-net is on the class path.
 */
public class FileSourceIncludeResolver implements IncludeResolver {

	@Override
	public Found find(String from, String name) throws IOException {
		FileSource f = locate(from, name);
		if( f == null || !f.isFile() ) {
			return null;
		}
		byte[] bytes;
		try (InputStream in = f.getInputStream()) {
			bytes = in.readAllBytes();
		}
		// (a filesource: URL's query holds connection settings and secrets)
		return new Found(f.getPath(), new ByteArrayInputStream(escape(decode(bytes))));
	}

	private static FileSource locate(String from, String name) throws IOException {
		boolean absolute = name.startsWith("/") || name.startsWith("\\") || name.matches("^[A-Za-z]:[\\\\/].*")
				|| name.matches("^[A-Za-z][A-Za-z0-9+.-]+:.*");
		if( !absolute && from != null ) {
			FileSource parent = FileSource.of(from).getParentFile();
			return parent == null ? null : parent.getChild(name);
		}
		return FileSource.of(name);
	}

	static String decode(byte[] bytes) {
		String text;
		try {
			text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
		} catch(CharacterCodingException e) {
			text = new String(bytes, StandardCharsets.ISO_8859_1);
		}
		return text.startsWith("﻿") ? text.substring(1) : text;
	}

	/** what Properties.load(InputStream) reads back as the same text */
	static byte[] escape(String text) {
		StringBuilder buf = new StringBuilder(text.length());
		for(int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if( c > 0x7e ) {
				buf.append(String.format("\\u%04x", (int) c));
			} else {
				buf.append(c);
			}
		}
		return buf.toString().getBytes(StandardCharsets.ISO_8859_1);
	}

}
