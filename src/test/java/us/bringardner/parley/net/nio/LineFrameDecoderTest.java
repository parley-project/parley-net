package us.bringardner.parley.net.nio;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.io.LineTooLongException;
import us.bringardner.parley.net.nio.LineFrameDecoder.LineEnd;

public class LineFrameDecoderTest {

	/**
	 * Feed the chunks one after another the way a connection does: bytes not consumed are kept
	 * and offered again with the next chunk.
	 */
	private static List<String> decodeAll(LineFrameDecoder decoder, String... chunks) throws IOException {
		List<String> ret = new ArrayList<String>();
		ByteBuffer in = ByteBuffer.allocate(8192);
		for (String chunk : chunks) {
			in.put(chunk.getBytes(StandardCharsets.UTF_8));
			in.flip();
			ByteBuffer frame;
			while( (frame = decoder.decode(in)) != null ) {
				ret.add(LineFrameDecoder.toString(frame));
			}
			in.compact();
		}
		return ret;
	}

	private static String repeat(char c, int n) {
		StringBuilder ret = new StringBuilder();
		for (int i = 0; i < n; i++) {
			ret.append(c);
		}
		return ret.toString();
	}

	private static LineFrameDecoder irc() {
		return new LineFrameDecoder(510, LineEnd.CR_OR_LF, true, true);
	}

	// The default, as before 2.0.0

	@Test
	public void defaultEndsAtLfOrCrLf() throws IOException {
		LineFrameDecoder d = new LineFrameDecoder();
		assertEquals(LineEnd.LF, d.getLineEnd());
		assertEquals(Arrays.asList("A", "B", "", "C\rD"), decodeAll(d, "A\nB\r\n\nC\rD\n"));
	}

	@Test
	public void defaultCrLfSplitAcrossReads() throws IOException {
		assertEquals(Arrays.asList("A", "B"), decodeAll(new LineFrameDecoder(), "A\r", "\nB\n"));
	}

	@Test
	public void defaultLongLineIsAnError() {
		assertThrows(LineTooLongException.class, () -> decodeAll(new LineFrameDecoder(5), "123456\n"));
		assertThrows(LineTooLongException.class, () -> decodeAll(new LineFrameDecoder(5), "1234567"));
		// over the limit by more than a possible CR, across reads
		assertThrows(LineTooLongException.class, () -> decodeAll(new LineFrameDecoder(5), "12345", "67"));
	}

	@Test
	public void defaultLineOfExactlyTheLimit() throws IOException {
		assertEquals(Arrays.asList("12345"), decodeAll(new LineFrameDecoder(5), "12345\r", "\n"));
	}

	// CR LF only

	@Test
	public void crLfOnly() throws IOException {
		LineFrameDecoder d = new LineFrameDecoder(100, LineEnd.CRLF, false, false);
		assertEquals(Arrays.asList("A\nB", "C\rD", ""), decodeAll(d, "A\nB\r\nC\rD\r\n\r\n"));
		assertEquals(Arrays.asList("A"), decodeAll(new LineFrameDecoder(100, LineEnd.CRLF, false, false), "A\r", "\n"));
	}

	// CR, LF or CR LF (IRC)

	@Test
	public void crOrLf() throws IOException {
		assertEquals(Arrays.asList("A", "B", "C", "D"), decodeAll(irc(), "A\r\nB\rC\nD\r\n"));
	}

	@Test
	public void emptyLinesSkipped() throws IOException {
		assertEquals(Arrays.asList("A", "B"), decodeAll(irc(), "\r\n\r\nA\n\n\rB\r\n"));
		// and kept when not skipping
		LineFrameDecoder keep = new LineFrameDecoder(100, LineEnd.CR_OR_LF, false, false);
		assertEquals(Arrays.asList("A", "", "B"), decodeAll(keep, "A\n\nB\r\n"));
	}

	@Test
	public void crOrLfWithCrLfSplitAcrossReads() throws IOException {
		assertEquals(Arrays.asList("NICK a", "USER b"), decodeAll(irc(), "NICK a\r", "\nUSER b\r\n"));
		// without skipping empty lines, the LF after a CR at the end of a read is still not a line
		LineFrameDecoder keep = new LineFrameDecoder(100, LineEnd.CR_OR_LF, false, false);
		assertEquals(Arrays.asList("A", "B"), decodeAll(keep, "A\r", "\nB\n"));
	}

	@Test
	public void partialLineWaits() throws IOException {
		assertEquals(Arrays.asList("PRIVMSG a b"), decodeAll(irc(), "PRIV", "MSG a", " b\n"));
	}

	// Cutting long lines

	@Test
	public void longLineIsCut() throws IOException {
		List<String> got = decodeAll(irc(), repeat('x', 700)+"\r\nNEXT\r\n");
		assertEquals(Arrays.asList(repeat('x', 510), "NEXT"), got);
	}

	@Test
	public void longLineCutAcrossReads() throws IOException {
		String part = repeat('y', 300);
		assertEquals(Arrays.asList(repeat('y', 510), "NEXT"), decodeAll(irc(), part, part, part+"\nNEXT\n"));
	}

	@Test
	public void longLineCutWithCrLfSplitAcrossReads() throws IOException {
		LineFrameDecoder d = new LineFrameDecoder(5, LineEnd.CRLF, false, true);
		assertEquals(Arrays.asList("12345", "NEXT"), decodeAll(d, "1234567890\r", "\nNEXT\r\n"));
		LineFrameDecoder lf = new LineFrameDecoder(5, LineEnd.LF, false, true);
		assertEquals(Arrays.asList("12345", "NEXT"), decodeAll(lf, "1234567890", "abc\r", "\nNEXT\n"));
	}

	@Test
	public void cutKeepsUtf8Whole() throws IOException {
		LineFrameDecoder d = new LineFrameDecoder(11, LineEnd.CR_OR_LF, true, true);
		// 1 + 5 two-byte characters = 11 bytes; the 6th would be split
		assertEquals(Arrays.asList("a"+repeat('é', 5)), decodeAll(d, "a"+repeat('é', 400)+"\n"));
		LineFrameDecoder d2 = new LineFrameDecoder(10, LineEnd.CR_OR_LF, true, true);
		assertEquals(Arrays.asList("a"+repeat('é', 4)), decodeAll(d2, "a"+repeat('é', 400)+"\n"));
	}

	@Test
	public void tooLongIsAnErrorWhenNotCutting() {
		LineFrameDecoder d = new LineFrameDecoder(510, LineEnd.CR_OR_LF, true, false);
		assertThrows(LineTooLongException.class, () -> decodeAll(d, repeat('z', 600)+"\n"));
		LineFrameDecoder d2 = new LineFrameDecoder(510, LineEnd.CR_OR_LF, true, false);
		assertThrows(LineTooLongException.class, () -> decodeAll(d2, repeat('z', 600)));
	}

	@Test
	public void options() {
		LineFrameDecoder d = irc();
		assertEquals(510, d.getMaxLineLength());
		assertEquals(LineEnd.CR_OR_LF, d.getLineEnd());
		assertEquals(true, d.isSkipEmptyLines());
		assertEquals(true, d.isTruncateLongLines());
		assertThrows(IllegalArgumentException.class, () -> new LineFrameDecoder(0));
		assertThrows(IllegalArgumentException.class, () -> new LineFrameDecoder(10, null, false, false));
	}
}
