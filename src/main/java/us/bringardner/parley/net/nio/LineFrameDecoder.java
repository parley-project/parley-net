/**
 * <PRE>
 *
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 *
 *
 */
package us.bringardner.parley.net.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import us.bringardner.parley.io.LineTooLongException;

/**
 * Splits the input into lines. The frames don't include the line end.
 * <p>
 * By default a line ends in LF or CR LF, and a line over the limit throws parley-io's
 * LineTooLongException, as the framework's line readers do. A protocol can choose:
 * <ul>
 * <li>{@link LineEnd how a line ends}: LF (a CR before it is dropped), CR LF only (a lone CR or LF
 * is part of the line), or any of CR, LF and CR LF (IRC, RFC 2812 section 2.3.1)</li>
 * <li>to skip empty lines instead of passing them on as empty frames</li>
 * <li>to cut a line over the limit instead of failing: the frame is its first bytes (fewer when
 * that keeps a UTF-8 character whole) and the rest of the line, up to its end, is dropped</li>
 * </ul>
 * <pre>
 * // IRC: CR, LF or CR LF; empty lines skipped; 510 bytes, longer lines cut
 * new LineFrameDecoder(510, LineFrameDecoder.LineEnd.CR_OR_LF, true, true)
 * </pre>
 *
 * @author Tony Bringardner
 */
public class LineFrameDecoder implements IFrameDecoder {

	/** How a line ends */
	public enum LineEnd {
		/** LF; a CR just before it is dropped too, so CR LF works (the default) */
		LF,
		/** CR LF only; a CR or LF on its own is part of the line */
		CRLF,
		/** CR, LF or CR LF (IRC, RFC 2812 section 2.3.1) */
		CR_OR_LF
	}

	/** Longest line accepted by default (bytes, not counting the line end) */
	public static final int DEFAULT_MAX_LINE_LENGTH = 64*1024;

	private final int maxLineLength;
	private final LineEnd lineEnd;
	private final boolean skipEmptyLines;
	private final boolean truncateLongLines;
	// How far past the position the last call looked for a line end, so a long line isn't scanned again
	private int scanned;
	// CR_OR_LF: a line ended in CR at the end of the input, so a LF that comes next belongs to it
	private boolean skipLf;
	// truncateLongLines: the start of a line that was too long, kept while the rest of it is dropped
	private ByteBuffer cut;

	public LineFrameDecoder() {
		this(DEFAULT_MAX_LINE_LENGTH);
	}

	/**
	 * Lines end in LF or CR LF, empty lines are frames, and a line over the limit is an error.
	 *
	 * @param maxLineLength longest line accepted (bytes, without the line end). Without a limit
	 * a peer could use up the input buffer by never sending a line end.
	 */
	public LineFrameDecoder(int maxLineLength) {
		this(maxLineLength, LineEnd.LF, false, false);
	}

	/**
	 * @param maxLineLength longest line accepted (bytes, without the line end)
	 * @param lineEnd how a line ends
	 * @param skipEmptyLines true to skip empty lines, false to pass them on as empty frames
	 * @param truncateLongLines true to cut a line over the limit, false to throw LineTooLongException
	 * (which closes the connection)
	 * @since 2.0.0
	 */
	public LineFrameDecoder(int maxLineLength, LineEnd lineEnd, boolean skipEmptyLines, boolean truncateLongLines) {
		if( maxLineLength <= 0 ) {
			throw new IllegalArgumentException("maxLineLength must be > 0");
		}
		if( lineEnd == null ) {
			throw new IllegalArgumentException("lineEnd must not be null");
		}
		this.maxLineLength = maxLineLength;
		this.lineEnd = lineEnd;
		this.skipEmptyLines = skipEmptyLines;
		this.truncateLongLines = truncateLongLines;
	}

	public int getMaxLineLength() {
		return maxLineLength;
	}

	/** @since 2.0.0 */
	public LineEnd getLineEnd() {
		return lineEnd;
	}

	/** @since 2.0.0 */
	public boolean isSkipEmptyLines() {
		return skipEmptyLines;
	}

	/** @since 2.0.0 */
	public boolean isTruncateLongLines() {
		return truncateLongLines;
	}

	@Override
	public ByteBuffer decode(ByteBuffer in) throws IOException {
		while( in.hasRemaining() ) {
			if( skipLf ) {
				skipLf = false;
				if( in.get(in.position()) == '\n' ) {
					in.position(in.position()+1);
					continue;
				}
			}
			int start = in.position();
			int limit = in.limit();
			// The line's last byte + 1 (where its line end starts), and the first byte after the line end
			int contentEnd = -1;
			int next = -1;
			for (int i = start+scanned; i < limit; i++) {
				byte b = in.get(i);
				if( lineEnd == LineEnd.CR_OR_LF ) {
					if( b == '\r' || b == '\n' ) {
						contentEnd = i;
						next = i+1;
						if( b == '\r' ) {
							if( next < limit ) {
								if( in.get(next) == '\n' ) {
									next++;
								}
							} else {
								skipLf = true;
							}
						}
						break;
					}
				} else if( b == '\n' ) {
					boolean cr = i > start && in.get(i-1) == '\r';
					if( lineEnd == LineEnd.CRLF && !cr ) {
						continue;
					}
					contentEnd = cr ? i-1 : i;
					next = i+1;
					break;
				}
			}
			if( contentEnd < 0 ) {
				noLineEndYet(in, start, limit);
				return null;
			}
			scanned = 0;
			int len = contentEnd-start;
			ByteBuffer frame;
			if( cut != null ) {
				frame = cut;
				cut = null;
			} else if( len > maxLineLength ) {
				if( !truncateLongLines ) {
					throw new LineTooLongException(maxLineLength);
				}
				frame = cutCopy(in, start, len);
			} else {
				frame = IFrameDecoder.copy(in, len);
			}
			in.position(next);
			if( frame.hasRemaining() || !skipEmptyLines ) {
				return frame;
			}
		}
		return null;
	}

	// No line end in the input: wait for more, or deal with a line that is already too long
	private void noLineEndYet(ByteBuffer in, int start, int limit) throws IOException {
		scanned = limit-start;
		// A CR that may be followed by a LF isn't counted (LF and CRLF)
		int slack = lineEnd == LineEnd.CR_OR_LF ? 0 : 1;
		if( cut == null && scanned <= maxLineLength+slack ) {
			return;
		}
		if( cut == null ) {
			if( !truncateLongLines ) {
				throw new LineTooLongException(maxLineLength);
			}
			cut = cutCopy(in, start, scanned);
		}
		// Drop what has come of the line, but keep the last byte: it may be the CR of a CR LF
		in.position(limit-1);
		scanned = 1;
	}

	// A copy of the first maxLineLength bytes of a line of len bytes at start (fewer, to keep a UTF-8 character whole)
	private ByteBuffer cutCopy(ByteBuffer in, int start, int len) {
		int keep = maxLineLength;
		// Back up over UTF-8 continuation bytes (10xxxxxx) to the start of the character that would be split
		int back = 0;
		while( keep > 0 && back < 3 && keep < len && (in.get(start+keep) & 0xC0) == 0x80 ) {
			keep--;
			back++;
		}
		if( keep < len && (in.get(start+keep) & 0xC0) == 0x80 ) {
			// Not UTF-8: cut at the limit
			keep = maxLineLength;
		}
		ByteBuffer src = in.duplicate();
		src.position(start);
		src.limit(start+keep);
		ByteBuffer ret = ByteBuffer.allocate(keep);
		ret.put(src);
		ret.flip();
		return ret;
	}

	/**
	 * @return the frame as a UTF-8 string
	 */
	public static String toString(ByteBuffer frame) {
		return StandardCharsets.UTF_8.decode(frame.duplicate()).toString();
	}
}
