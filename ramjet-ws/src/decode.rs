//! The incremental frame decoder.

use std::ops::Range;

use crate::mask;
use crate::utf8::{self, Utf8};
use crate::{CloseFrame, Error, Event, MessageKind};

/// Default ceiling on a reassembled message: 16 MiB.
pub const DEFAULT_MAX_MESSAGE: usize = 16 * 1024 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Close codes RFC 6455 §7.4 permits to appear in a Close payload.
///
/// 1004 was never assigned, and 1005/1006 exist only to be reported locally by
/// an API — putting either on the wire is a protocol error. Everything from
/// 1012 to 2999 is reserved for the RFC and its registry, so a peer must not
/// invent one; 3000-3999 belong to libraries and 4000-4999 to applications.
fn close_code_is_valid(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

/// A frame header, validated as far as one frame can be without knowing what
/// came before it.
struct Header {
    fin: bool,
    opcode: u8,
    mask: [u8; 4],
    len: u64,
    /// Bytes the header itself occupies.
    header_len: usize,
}

/// Parse and validate one frame header.
///
/// Everything checked here is a property of the frame alone — the reserved
/// bits, the opcode, the mask a client is required to set, the limits on a
/// control frame — so the streaming path and the in-place path share it and
/// cannot drift apart. Rules that depend on what came before, like the
/// fragmentation sequence, belong to the caller.
///
/// `Ok(None)` means the header is not all here yet. Nothing is consumed.
fn parse_header(bytes: &[u8]) -> Result<Option<Header>, Error> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (bytes[0], bytes[1]);

    let fin = b0 & 0x80 != 0;
    if b0 & 0x70 != 0 {
        return Err(Error::Protocol(
            "reserved bit set but no extension was negotiated",
        ));
    }
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;

    // 0-125 is the length itself; 126 means a 16-bit length follows and 127
    // a 64-bit one. Non-minimal encodings are legal and accepted.
    let (len, len_bytes) = match b1 & 0x7F {
        126 => {
            if bytes.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([bytes[2], bytes[3]])), 2)
        }
        127 => {
            if bytes.len() < 10 {
                return Ok(None);
            }
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&bytes[2..10]);
            let len = u64::from_be_bytes(wide);
            if len & (1 << 63) != 0 {
                return Err(Error::Protocol("64-bit length has the high bit set"));
            }
            (len, 8)
        }
        short => (u64::from(short), 0),
    };

    let header_len = 2 + len_bytes + if masked { 4 } else { 0 };
    if bytes.len() < header_len {
        return Ok(None);
    }

    match opcode {
        OP_CONTINUATION | OP_TEXT | OP_BINARY => {}
        OP_CLOSE | OP_PING | OP_PONG => {
            if !fin {
                return Err(Error::Protocol("control frames must not be fragmented"));
            }
            if len > 125 {
                return Err(Error::Protocol("control frame payload exceeds 125 bytes"));
            }
        }
        0x3..=0x7 => return Err(Error::Protocol("reserved non-control opcode")),
        _ => return Err(Error::Protocol("reserved control opcode")),
    }

    // Server role: every frame from a client carries a mask.
    if !masked {
        return Err(Error::Protocol("client frames must be masked"));
    }

    let mut mask = [0u8; 4];
    mask.copy_from_slice(&bytes[header_len - 4..header_len]);
    Ok(Some(Header {
        fin,
        opcode,
        mask,
        len,
        header_len,
    }))
}

/// Where a complete frame's payload ended up, for a caller that wants to reply
/// out of the same buffer it read into. Produced by
/// [`Decoder::take_whole_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholeFrame {
    /// Whether the message was text or binary. Text has already been validated
    /// as UTF-8.
    pub kind: MessageKind,
    /// The unmasked payload's position in the buffer that was handed in.
    ///
    /// Everything before `payload.start` is the client's masked header, which is
    /// always at least four bytes longer than the reply header a server needs —
    /// so a reply header fits in front of the payload with room to spare.
    pub payload: Range<usize>,
}

/// A complete data frame transformed into its server-side echo representation.
///
/// Produced by [`Decoder::take_echo_frame_at`]. `frame` is ready to write,
/// `payload` identifies the validated unmasked data inside it, and `consumed`
/// is where the original client frame ended so a caller can continue walking a
/// pipelined receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoFrame {
    /// The complete unmasked server frame, including its header.
    pub frame: Range<usize>,
    /// The echoed payload inside [`Self::frame`].
    pub payload: Range<usize>,
    /// End of the original masked client frame in the receive buffer.
    pub consumed: usize,
}

struct DataFrame {
    kind: MessageKind,
    opcode: u8,
    mask: [u8; 4],
    payload: Range<usize>,
}

/// The frame currently being read. Small and `Copy` so the payload loop can
/// hold it while it borrows the decoder's buffers.
#[derive(Debug, Clone, Copy)]
struct Frame {
    fin: bool,
    opcode: u8,
    mask: [u8; 4],
    /// Payload bytes still owed to this frame.
    remaining: usize,
    /// How far into the four-byte mask the payload has got. Kept across chunk
    /// boundaries, since the mask repeats over the whole payload and not over
    /// whatever slice happened to arrive.
    mask_pos: usize,
}

/// Turns a stream of bytes into [`Event`]s.
///
/// Feed it whatever you read and pull events until it asks for more. It holds
/// on to a partial frame across calls, so the split points in the byte stream
/// never change what comes out.
///
/// ```
/// use ramjet_ws::{Decoder, Event};
///
/// let mut d = Decoder::new();
/// // One masked "Hi" frame, delivered one byte at a time.
/// for byte in [0x81, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93] {
///     d.feed(&[byte]);
/// }
/// assert_eq!(d.next_event().unwrap(), Some(Event::Text("Hi".into())));
/// assert_eq!(d.next_event().unwrap(), None);
/// ```
#[derive(Debug)]
pub struct Decoder {
    /// Unread input. Compacted at the start of every `feed`.
    buf: Vec<u8>,
    pos: usize,
    max_message: usize,
    frame: Option<Frame>,
    /// Opcode of the data message open across fragments, if any.
    open: Option<u8>,
    /// Payload of that message, reassembled.
    msg: Vec<u8>,
    /// UTF-8 state for it, carried across every fragment and every chunk.
    utf8: Utf8,
    /// Payload of the control frame being read. Separate from `msg` because a
    /// control frame may arrive between two fragments of a data message.
    ctrl: Vec<u8>,
    /// Once the stream is bad it stays bad; the same error is returned forever.
    failed: Option<Error>,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder with the default 16 MiB message ceiling.
    pub fn new() -> Self {
        Decoder::with_max_message(DEFAULT_MAX_MESSAGE)
    }

    /// A decoder that refuses any message larger than `max_message` bytes.
    ///
    /// The limit is checked against the frame header, so an oversized message
    /// costs an [`Error::TooLarge`] and never the allocation.
    pub fn with_max_message(max_message: usize) -> Self {
        Decoder {
            buf: Vec::new(),
            pos: 0,
            max_message,
            frame: None,
            open: None,
            msg: Vec::new(),
            utf8: Utf8::default(),
            ctrl: Vec::new(),
            failed: None,
        }
    }

    /// The configured message ceiling, in bytes.
    pub fn max_message(&self) -> usize {
        self.max_message
    }

    /// Nothing buffered, nothing half-read, no message open: the stream's
    /// position is exactly the start of whatever comes next.
    fn is_idle(&self) -> bool {
        self.failed.is_none()
            && self.frame.is_none()
            && self.open.is_none()
            && self.pos == self.buf.len()
    }

    /// If `buf` holds exactly one complete, unfragmented data frame, unmask it
    /// where it lies and report where the payload ended up.
    ///
    /// This is the zero-copy path. A server echoing a message can reply out of
    /// the very buffer it read into: the client's masked header is at least four
    /// bytes longer than the reply header a server writes, so the reply header
    /// fits in front of the payload without moving a byte of it.
    ///
    /// `Ok(None)` means the fast path does not apply and **nothing has been
    /// touched** — feed `buf` to [`Decoder::feed`] as usual. That covers a
    /// buffer holding a partial frame, more than one frame, a fragment, or a
    /// control frame, and a decoder that is mid-stream and so has state of its
    /// own that `buf` alone cannot be interpreted against.
    ///
    /// For a buffer holding a pipelined batch of frames, see
    /// [`Decoder::take_frame_at`].
    ///
    /// An `Err` is a real protocol violation, terminal exactly as it would be
    /// from [`Decoder::next_event`], and the decoder stays failed afterwards.
    ///
    /// Text payloads are validated as UTF-8 before returning, so the guarantee
    /// on [`Event::Text`] holds here too.
    pub fn take_whole_frame(&mut self, buf: &mut [u8]) -> Result<Option<WholeFrame>, Error> {
        self.take_data_frame(buf, 0, true)
    }

    /// Unmask the next complete, unfragmented data frame beginning at `from`,
    /// and report where its payload ended up.
    ///
    /// [`Decoder::take_whole_frame`] generalised to a buffer holding more than
    /// one frame, which is what a pipelining client produces: start with
    /// `from = 0` and then pass the previous call's `payload.end`, until it
    /// declines. The returned range is absolute in `buf`, and the frame occupies
    /// exactly `..payload.end` from `from`, so `payload.end` is both the end of
    /// this frame and the start of the next.
    ///
    /// Every reply header a server writes is at least four bytes shorter than
    /// the masked client header it replaces, so replies to a whole batch always
    /// fit inside the buffer the batch arrived in — each one four bytes further
    /// ahead of its payload than the last.
    ///
    /// `Ok(None)` leaves `buf` untouched from `from` onwards and means the bytes
    /// there are not a whole data frame: a partial frame, a fragment, or a
    /// control frame. Feed `buf[from..]` to [`Decoder::feed`] as usual. Frames
    /// already taken by earlier calls stay taken — they were whole, and the
    /// decoder never saw them.
    ///
    /// `Err` and the text-validation guarantee are exactly as for
    /// [`Decoder::take_whole_frame`].
    ///
    /// ```
    /// use ramjet_ws::{Decoder, MessageKind};
    ///
    /// // Two masked one-byte text frames, back to back.
    /// let mut buf = vec![
    ///     0x81, 0x81, 0x00, 0x00, 0x00, 0x00, b'a', //
    ///     0x81, 0x81, 0x00, 0x00, 0x00, 0x00, b'b',
    /// ];
    /// let mut d = Decoder::new();
    /// let first = d.take_frame_at(&mut buf, 0).unwrap().unwrap();
    /// assert_eq!(first.kind, MessageKind::Text);
    /// assert_eq!(buf[first.payload.clone()], *b"a");
    /// let second = d.take_frame_at(&mut buf, first.payload.end).unwrap().unwrap();
    /// assert_eq!(buf[second.payload.clone()], *b"b");
    /// assert_eq!(d.take_frame_at(&mut buf, second.payload.end).unwrap(), None);
    /// ```
    pub fn take_frame_at(
        &mut self,
        buf: &mut [u8],
        from: usize,
    ) -> Result<Option<WholeFrame>, Error> {
        self.take_data_frame(buf, from, false)
    }

    /// Transform the next whole data frame into a ready-to-write server echo.
    ///
    /// The original masked client frame starts at `from`; the shorter unmasked
    /// server frame is packed at `to`. The payload is unmasked directly into
    /// its final position, fusing the XOR and overlapping compaction into one
    /// pass. This is intended for pipelined receive buffers where several
    /// replies are packed back-to-back before one write.
    ///
    /// `to` must not be after `from`. `Ok(None)` means the fast path does not
    /// apply or the output would not fit, and leaves the buffer untouched.
    /// Fragmented and control frames remain the streaming decoder's job.
    pub fn take_echo_frame_at(
        &mut self,
        buf: &mut [u8],
        from: usize,
        to: usize,
    ) -> Result<Option<EchoFrame>, Error> {
        if to > from {
            return Ok(None);
        }
        let Some(data) = self.inspect_data_frame(buf, from, false)? else {
            return Ok(None);
        };

        let len = data.payload.len();
        let (header, header_len) = crate::encode::header_bytes(true, data.opcode, len);
        let Some(payload_start) = to.checked_add(header_len) else {
            return Ok(None);
        };
        let Some(frame_end) = payload_start.checked_add(len) else {
            return Ok(None);
        };
        if frame_end > buf.len() || payload_start > data.payload.start {
            return Ok(None);
        }

        let consumed = data.payload.end;
        mask::unmask_into(buf, data.payload, payload_start, data.mask, 0);
        let payload = payload_start..frame_end;
        if data.kind == MessageKind::Text && !utf8::is_valid(&buf[payload.clone()]) {
            let e = Error::InvalidUtf8;
            self.failed = Some(e.clone());
            return Err(e);
        }
        buf[to..to + header_len].copy_from_slice(&header[..header_len]);

        Ok(Some(EchoFrame {
            frame: to..frame_end,
            payload,
            consumed,
        }))
    }

    /// The shared body. `must_fill` is what separates the single-frame promise
    /// from the batch one: with it set, a frame that does not reach the end of
    /// `buf` is declined rather than taken, because the caller of
    /// [`Decoder::take_whole_frame`] has nowhere to put the remainder.
    fn take_data_frame(
        &mut self,
        buf: &mut [u8],
        from: usize,
        must_fill: bool,
    ) -> Result<Option<WholeFrame>, Error> {
        let Some(data) = self.inspect_data_frame(buf, from, must_fill)? else {
            return Ok(None);
        };

        // Committed: unmask in place. The mask repeats over the payload from its
        // own start, not from the start of the buffer, so the phase is zero.
        mask::unmask(&mut buf[data.payload.clone()], data.mask, 0);
        if data.kind == MessageKind::Text && !utf8::is_valid(&buf[data.payload.clone()]) {
            let e = Error::InvalidUtf8;
            self.failed = Some(e.clone());
            return Err(e);
        }
        Ok(Some(WholeFrame {
            kind: data.kind,
            payload: data.payload,
        }))
    }

    /// Validate and describe a whole, unfragmented data frame without touching
    /// its bytes. Both in-place paths commit only after this succeeds.
    fn inspect_data_frame(
        &mut self,
        buf: &[u8],
        from: usize,
        must_fill: bool,
    ) -> Result<Option<DataFrame>, Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        if !self.is_idle() || from > buf.len() {
            return Ok(None);
        }
        let header = match parse_header(&buf[from..]) {
            Ok(Some(h)) => h,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.failed = Some(e.clone());
                return Err(e);
            }
        };
        let kind = match header.opcode {
            OP_TEXT => MessageKind::Text,
            OP_BINARY => MessageKind::Binary,
            _ => return Ok(None),
        };
        if !header.fin {
            return Ok(None);
        }
        let start = from + header.header_len;
        let payload = start..start + header.len as usize;
        if payload.end > buf.len() || (must_fill && payload.end != buf.len()) {
            return Ok(None);
        }
        if header.len > self.max_message as u64 {
            let e = Error::TooLarge {
                limit: self.max_message,
            };
            self.failed = Some(e.clone());
            return Err(e);
        }

        Ok(Some(DataFrame {
            kind,
            opcode: header.opcode,
            mask: header.mask,
            payload,
        }))
    }

    /// Hand the decoder more bytes. Any amount, split anywhere.
    pub fn feed(&mut self, bytes: &[u8]) {
        // Drop what has already been decoded before growing the buffer, so a
        // long-lived connection does not accumulate its whole history.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Pull the next complete event.
    ///
    /// `Ok(None)` means the bytes so far do not finish anything — feed more.
    /// An `Err` is terminal: the stream cannot be resynchronised, so every
    /// later call returns that same error and the caller should send a Close
    /// with [`Error::close_code`] and hang up.
    pub fn next_event(&mut self) -> Result<Option<Event>, Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        match self.step() {
            Err(e) => {
                self.failed = Some(e.clone());
                Err(e)
            }
            ok => ok,
        }
    }

    fn step(&mut self) -> Result<Option<Event>, Error> {
        loop {
            if self.frame.is_none() {
                match self.read_header()? {
                    Some(f) => self.frame = Some(f),
                    None => return Ok(None),
                }
            }
            if let Some(event) = self.read_payload()? {
                return Ok(Some(event));
            }
            // Either the frame is unfinished and wants more bytes, or it
            // finished without producing an event (a non-final fragment).
            if self.frame.is_some() {
                return Ok(None);
            }
        }
    }

    /// Parse a frame header if one is fully present, and set up the message
    /// state it implies. Returns `None` when more bytes are needed.
    fn read_header(&mut self) -> Result<Option<Frame>, Error> {
        let Some(h) = parse_header(&self.buf[self.pos..])? else {
            return Ok(None);
        };
        let Header {
            fin,
            opcode,
            mask,
            len,
            header_len,
        } = h;

        let is_data = matches!(opcode, OP_CONTINUATION | OP_TEXT | OP_BINARY);
        if is_data {
            match opcode {
                OP_TEXT | OP_BINARY if self.open.is_some() => {
                    return Err(Error::Protocol(
                        "data frame arrived while a fragmented message was still open",
                    ));
                }
                OP_CONTINUATION if self.open.is_none() => {
                    return Err(Error::Protocol("continuation frame with no message open"));
                }
                _ => {}
            }
            // Checked from the header, so the bytes are never allocated.
            if self.msg.len() as u64 + len > self.max_message as u64 {
                return Err(Error::TooLarge {
                    limit: self.max_message,
                });
            }
        }

        self.pos += header_len;

        if matches!(opcode, OP_TEXT | OP_BINARY) {
            self.open = Some(opcode);
            self.msg.clear();
            self.utf8 = Utf8::default();
        }
        if !is_data {
            self.ctrl.clear();
        }

        Ok(Some(Frame {
            fin,
            opcode,
            mask,
            // `len` is bounded by max_message for data frames and by 125 for
            // control frames, so this fits usize on any target worth serving.
            remaining: len as usize,
            mask_pos: 0,
        }))
    }

    /// Consume as much of the current frame's payload as has arrived.
    ///
    /// Returns the event if this completed one. Leaves `self.frame` set when
    /// the frame still wants bytes, and clears it when the frame is done.
    fn read_payload(&mut self) -> Result<Option<Event>, Error> {
        let Some(mut f) = self.frame else {
            return Ok(None);
        };

        let take = (self.buf.len() - self.pos).min(f.remaining);
        if take > 0 {
            let (start, end) = (self.pos, self.pos + take);
            // Unmask in place. The mask repeats over the payload as a whole, so
            // the phase comes from `mask_pos`, not from the start of this slice.
            mask::unmask(&mut self.buf[start..end], f.mask, f.mask_pos);
            let is_data = matches!(f.opcode, OP_CONTINUATION | OP_TEXT | OP_BINARY);
            if is_data {
                // Validate text as it arrives rather than at the end of the
                // message: a bad sequence is rejected on the byte that
                // completes it, however the stream was chunked.
                if self.open == Some(OP_TEXT) && !self.utf8.push_all(&self.buf[start..end]) {
                    return Err(Error::InvalidUtf8);
                }
                self.msg.extend_from_slice(&self.buf[start..end]);
            } else {
                self.ctrl.extend_from_slice(&self.buf[start..end]);
            }
            self.pos = end;
            f.remaining -= take;
            f.mask_pos += take;
        }

        if f.remaining > 0 {
            self.frame = Some(f);
            return Ok(None);
        }
        self.frame = None;
        self.finish_frame(f)
    }

    /// Turn a fully-read frame into an event, if it makes one.
    fn finish_frame(&mut self, f: Frame) -> Result<Option<Event>, Error> {
        match f.opcode {
            OP_PING => Ok(Some(Event::Ping(std::mem::take(&mut self.ctrl)))),
            OP_PONG => Ok(Some(Event::Pong(std::mem::take(&mut self.ctrl)))),
            OP_CLOSE => self.finish_close(),
            _ => {
                if !f.fin {
                    return Ok(None); // more fragments to come
                }
                let kind = self.open.take();
                let payload = std::mem::take(&mut self.msg);
                if kind == Some(OP_TEXT) {
                    // A message that ends mid-sequence is truncated, not merely
                    // unfinished.
                    if !self.utf8.is_complete() {
                        return Err(Error::InvalidUtf8);
                    }
                    let text = String::from_utf8(payload).map_err(|_| Error::InvalidUtf8)?;
                    Ok(Some(Event::Text(text)))
                } else {
                    Ok(Some(Event::Binary(payload)))
                }
            }
        }
    }

    fn finish_close(&mut self) -> Result<Option<Event>, Error> {
        let payload = std::mem::take(&mut self.ctrl);
        if payload.is_empty() {
            return Ok(Some(Event::Close(None)));
        }
        if payload.len() < 2 {
            return Err(Error::Protocol(
                "close payload must be empty or carry a two-byte code",
            ));
        }
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        if !close_code_is_valid(code) {
            return Err(Error::Protocol("close code is reserved or not assigned"));
        }
        if !utf8::is_valid(&payload[2..]) {
            return Err(Error::InvalidUtf8);
        }
        let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| Error::InvalidUtf8)?;
        Ok(Some(Event::Close(Some(CloseFrame { code, reason }))))
    }
}
