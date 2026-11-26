//! Newline-delimited JSON framing (`toolbus.sock`, `crawler.sock`, `learn.sock`, `--stdio`).
//!
//! One UTF-8 JSON value per line. [`NdjsonDecoder`] is a push parser: feed it whatever a
//! `read()` returned, then drain complete lines. It never performs I/O and never blocks.
//!
//! Behaviour on hostile input:
//!
//! * A line longer than the limit yields one [`CodecError::LineTooLong`]; the rest of that
//!   line is discarded without buffering it, and decoding resumes at the next line.
//! * Blank (whitespace-only) lines are ignored. A trailing `\r` is stripped (CRLF tolerated).
//! * Bytes after the last newline are held until more input arrives; if the stream then
//!   ends, [`NdjsonDecoder::finish`] reports [`CodecError::Truncated`].
//!
//! Call [`NdjsonDecoder::next_line`] until it returns `None` after every
//! [`NdjsonDecoder::push`], and keep chunks modest (for example 64 KiB) so a single push
//! cannot allocate more than one chunk beyond the line limit.

use serde::Serialize;

use crate::errors::CodecError;
use crate::Limits;

/// Compact the internal buffer once at least this many consumed bytes pile up at its front.
const COMPACT_MIN: usize = 64 * 1024;

/// Incremental newline-delimited framing decoder.
#[derive(Debug)]
pub struct NdjsonDecoder {
    buf: Vec<u8>,
    /// Start of the first unconsumed byte in `buf`.
    head: usize,
    /// Everything in `buf[head..scanned]` is known to contain no newline.
    scanned: usize,
    /// Inside an over-long line: drop bytes until the next newline.
    discarding: bool,
    max_line: usize,
}

impl NdjsonDecoder {
    /// Creates a decoder that rejects lines longer than `max_line_bytes`.
    pub fn new(max_line_bytes: usize) -> Self {
        NdjsonDecoder { buf: Vec::new(), head: 0, scanned: 0, discarding: false, max_line: max_line_bytes }
    }

    /// Creates a decoder using [`Limits::max_line_bytes`].
    pub fn with_limits(limits: &Limits) -> Self {
        Self::new(limits.max_line_bytes)
    }

    /// Appends bytes read from the transport.
    pub fn push(&mut self, chunk: &[u8]) {
        if self.discarding {
            // Still inside an over-long line: skip everything up to and including the newline.
            match chunk.iter().position(|&b| b == b'\n') {
                None => return,
                Some(newline) => {
                    self.discarding = false;
                    self.buf.extend_from_slice(&chunk[newline + 1..]);
                    return;
                }
            }
        }
        self.buf.extend_from_slice(chunk);
    }

    /// Returns the next complete line without its terminator, `Some(Err(_))` for an
    /// over-long line, or `None` when more input is needed.
    pub fn next_line(&mut self) -> Option<Result<Vec<u8>, CodecError>> {
        loop {
            let from = self.scanned.max(self.head);
            let newline = self.buf[from..].iter().position(|&b| b == b'\n').map(|rel| from + rel);

            let Some(nl) = newline else {
                if self.discarding {
                    self.reset_buffer();
                    return None;
                }
                // One byte of slack: a maximal line may already be followed by its `\r`.
                if self.buf.len() - self.head > self.max_line.saturating_add(1) {
                    self.reset_buffer();
                    self.discarding = true;
                    return Some(Err(CodecError::LineTooLong { limit: self.max_line }));
                }
                self.scanned = self.buf.len();
                return None;
            };

            let start = self.head;
            self.head = nl + 1;
            self.scanned = self.head;

            if self.discarding {
                // This newline ends the over-long line we were skipping.
                self.discarding = false;
                self.compact();
                continue;
            }

            let mut end = nl;
            if end > start && self.buf[end - 1] == b'\r' {
                end -= 1;
            }
            if end - start > self.max_line {
                self.compact();
                return Some(Err(CodecError::LineTooLong { limit: self.max_line }));
            }
            if self.buf[start..end].iter().all(u8::is_ascii_whitespace) {
                self.compact();
                continue;
            }
            let line = self.buf[start..end].to_vec();
            self.compact();
            return Some(Ok(line));
        }
    }

    /// Call when the transport reaches end-of-stream. Returns [`CodecError::Truncated`] if
    /// a partial line is pending, and resets the decoder either way.
    pub fn finish(&mut self) -> Result<(), CodecError> {
        let dangling = !self.discarding && self.buf[self.head..].iter().any(|b| !b.is_ascii_whitespace());
        self.discarding = false;
        self.reset_buffer();
        if dangling {
            Err(CodecError::Truncated)
        } else {
            Ok(())
        }
    }

    fn reset_buffer(&mut self) {
        self.buf.clear();
        self.head = 0;
        self.scanned = 0;
    }

    fn compact(&mut self) {
        if self.head >= self.buf.len() {
            self.reset_buffer();
        } else if self.head >= COMPACT_MIN && self.head * 2 >= self.buf.len() {
            drop(self.buf.drain(..self.head));
            self.scanned = self.scanned.saturating_sub(self.head);
            self.head = 0;
        }
    }
}

/// Serialises `value` as one NDJSON line, terminator included.
///
/// `serde_json` escapes every control character inside strings, so compact output can
/// never contain a raw newline; the debug assertion documents that invariant.
pub fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(value)?;
    debug_assert!(!bytes.contains(&b'\n'));
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(dec: &mut NdjsonDecoder) -> Vec<Result<Vec<u8>, CodecError>> {
        let mut out = Vec::new();
        while let Some(item) = dec.next_line() {
            out.push(item);
        }
        out
    }

    fn lines(items: Vec<Result<Vec<u8>, CodecError>>) -> Vec<String> {
        items.into_iter().map(|r| String::from_utf8(r.unwrap()).unwrap()).collect()
    }

    #[test]
    fn splits_multiple_lines_from_one_chunk() {
        let mut d = NdjsonDecoder::new(1024);
        d.push(b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(lines(drain(&mut d)), vec![r#"{"a":1}"#, r#"{"b":2}"#]);
        assert!(d.next_line().is_none());
    }

    #[test]
    fn reassembles_lines_split_across_chunks_at_every_offset() {
        let data = b"{\"a\":1}\n{\"bb\":22}\n{\"c\":3}\n";
        for split in 0..=data.len() {
            let mut d = NdjsonDecoder::new(1024);
            let mut got = Vec::new();
            d.push(&data[..split]);
            got.extend(lines(drain(&mut d)));
            d.push(&data[split..]);
            got.extend(lines(drain(&mut d)));
            assert_eq!(got, vec![r#"{"a":1}"#, r#"{"bb":22}"#, r#"{"c":3}"#], "split at {split}");
        }
    }

    #[test]
    fn byte_at_a_time_delivery() {
        let mut d = NdjsonDecoder::new(1024);
        let mut got = Vec::new();
        for b in b"{\"a\":1}\n{\"b\":2}\n" {
            d.push(std::slice::from_ref(b));
            got.extend(lines(drain(&mut d)));
        }
        assert_eq!(got, vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    }

    #[test]
    fn tolerates_crlf_and_ignores_blank_lines() {
        let mut d = NdjsonDecoder::new(1024);
        d.push(b"\n\r\n{\"a\":1}\r\n   \n\n{\"b\":2}\n");
        assert_eq!(lines(drain(&mut d)), vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    }

    #[test]
    fn over_long_line_in_one_chunk_is_rejected_and_decoding_continues() {
        let mut d = NdjsonDecoder::new(8);
        d.push(b"123456789\n{\"a\":1}\n");
        let items = drain(&mut d);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], Err(CodecError::LineTooLong { limit: 8 }));
        assert_eq!(items[1], Ok(b"{\"a\":1}".to_vec()));
    }

    #[test]
    fn line_of_exactly_the_limit_is_accepted() {
        let mut d = NdjsonDecoder::new(8);
        d.push(b"12345678\n");
        assert_eq!(drain(&mut d), vec![Ok(b"12345678".to_vec())]);
        let mut d = NdjsonDecoder::new(8);
        d.push(b"12345678\r\n");
        assert_eq!(drain(&mut d), vec![Ok(b"12345678".to_vec())], "CR is not counted");
    }

    #[test]
    fn maximal_line_whose_cr_and_lf_arrive_separately_is_accepted() {
        let mut d = NdjsonDecoder::new(8);
        d.push(b"12345678\r"); // 9 pending bytes, but only 8 are content
        assert!(drain(&mut d).is_empty(), "must not be rejected before the newline arrives");
        d.push(b"\n");
        assert_eq!(drain(&mut d), vec![Ok(b"12345678".to_vec())]);
    }

    #[test]
    fn over_long_line_without_newline_is_discarded_and_resynchronises() {
        let mut d = NdjsonDecoder::new(16);
        d.push(&[b'A'; 40]);
        assert_eq!(drain(&mut d), vec![Err(CodecError::LineTooLong { limit: 16 })]);
        d.push(&[b'B'; 100]); // still the same line: dropped without buffering
        assert!(drain(&mut d).is_empty());
        assert!(d.buf.is_empty(), "discarded bytes must not be retained");
        d.push(b"BBBB\n{\"a\":1}\n");
        assert_eq!(drain(&mut d), vec![Ok(b"{\"a\":1}".to_vec())]);
    }

    #[test]
    fn over_long_line_arriving_in_small_chunks_is_reported_once() {
        // The good line `{"ok":true}` is 11 bytes, so a limit of 11 accepts it exactly.
        let mut d = NdjsonDecoder::new(11);
        let mut errors = 0;
        let mut ok = Vec::new();
        for chunk in b"0123456789012345678901234567890123\n{\"ok\":true}\n".chunks(3) {
            d.push(chunk);
            for item in drain(&mut d) {
                match item {
                    Ok(line) => ok.push(String::from_utf8(line).unwrap()),
                    Err(CodecError::LineTooLong { .. }) => errors += 1,
                    Err(other) => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(errors, 1);
        assert_eq!(ok, vec![r#"{"ok":true}"#]);
    }

    #[test]
    fn finish_reports_a_dangling_partial_line() {
        let mut d = NdjsonDecoder::new(1024);
        d.push(b"{\"a\":1}");
        assert!(d.next_line().is_none());
        assert_eq!(d.finish(), Err(CodecError::Truncated));
        assert_eq!(d.finish(), Ok(()), "finish resets the decoder");
    }

    #[test]
    fn finish_is_clean_after_complete_lines_and_whitespace() {
        let mut d = NdjsonDecoder::new(1024);
        d.push(b"{\"a\":1}\n  \r\n");
        assert_eq!(drain(&mut d).len(), 1);
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn finish_after_an_oversized_tail_is_not_an_extra_error() {
        let mut d = NdjsonDecoder::new(4);
        d.push(b"xxxxxxxxxx");
        assert_eq!(drain(&mut d), vec![Err(CodecError::LineTooLong { limit: 4 })]);
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn compaction_keeps_the_buffer_bounded_and_loses_nothing() {
        let mut data = Vec::new();
        for i in 0..50_000u32 {
            data.extend_from_slice(format!("{{\"n\":{i}}}\n").as_bytes());
        }
        let mut d = NdjsonDecoder::new(1024);
        d.push(&data); // one huge push: head will cross COMPACT_MIN while lines remain
        let mut count = 0u32;
        while let Some(item) = d.next_line() {
            assert_eq!(item.unwrap(), format!("{{\"n\":{count}}}").into_bytes());
            count += 1;
        }
        assert_eq!(count, 50_000);
        assert!(d.buf.is_empty());
    }

    #[test]
    fn invalid_utf8_is_framed_not_judged() {
        // Framing is byte-oriented; UTF-8 validity is serde_json's job downstream.
        let mut d = NdjsonDecoder::new(64);
        d.push(b"\xff\xfe\n");
        assert_eq!(drain(&mut d), vec![Ok(vec![0xff, 0xfe])]);
    }

    #[test]
    fn encode_line_appends_exactly_one_newline() {
        let value = serde_json::json!({"t": "a\nb"});
        let bytes = encode_line(&value).unwrap();
        assert_eq!(bytes, b"{\"t\":\"a\\nb\"}\n");
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
    }
}
