//! The `.ljar` file: a header, segments, and a checksummed footer index.
//!
//! ```text
//! "LOGJAR\0" version(1)          8 bytes
//! segment 0 .. segment n         see segment.rs
//! footer                         streams + per-segment index (varints)
//! trailer                        footer offset u64 | footer len u32 | crc32 u32 | "LJF1"
//! ```
//!
//! Appending never rewrites existing bytes: new segments and a new footer go
//! after the old footer, and the trailer at end-of-file names the live one.
//! If a crash leaves a torn tail, the reader scans backwards for the last
//! trailer whose checksum verifies, and the next append truncates the torn
//! bytes. So an archive is always readable as of its last completed write.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::segment::{self, Builder, Segment};
use crate::varint::{self, Cursor};
use crate::{par, Error, Result};

const HEADER: &[u8; 8] = b"LOGJAR\0\x01";
const TRAILER_MAGIC: &[u8; 4] = b"LJF1";
const TRAILER_LEN: u64 = 20;

/// One named input inside an archive, typically one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub name: String,
    /// The last line had no trailing newline; decoding must not add one.
    pub unterminated: bool,
}

/// What the footer records about each segment. Enough to plan a search
/// (which stream, which time range) without reading the segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentInfo {
    pub offset: u64,
    pub len: u64,
    pub stream: u32,
    pub lines: u64,
    pub raw_bytes: u64,
    /// Min/max timestamp in nanoseconds, over lines whose format has a year.
    pub time_range: Option<(i64, i64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub streams: Vec<StreamInfo>,
    pub segments: Vec<SegmentInfo>,
}

impl Index {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        varint::put_u64(&mut b, self.streams.len() as u64);
        for s in &self.streams {
            varint::put_bytes(&mut b, s.name.as_bytes());
            b.push(s.unterminated as u8);
        }
        varint::put_u64(&mut b, self.segments.len() as u64);
        for s in &self.segments {
            varint::put_u64(&mut b, s.offset);
            varint::put_u64(&mut b, s.len);
            varint::put_u64(&mut b, s.stream as u64);
            varint::put_u64(&mut b, s.lines);
            varint::put_u64(&mut b, s.raw_bytes);
            match s.time_range {
                Some((lo, hi)) => {
                    b.push(1);
                    varint::put_i64(&mut b, lo);
                    varint::put_i64(&mut b, hi);
                }
                None => b.push(0),
            }
        }
        b
    }

    fn decode(buf: &[u8]) -> Result<Index> {
        let mut c = Cursor::new(buf);
        let n = c.usize()?;
        let mut streams = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let name = String::from_utf8(c.bytes()?.to_vec())
                .map_err(|_| Error::Corrupt("stream name"))?;
            let unterminated = c.take(1)?[0] == 1;
            streams.push(StreamInfo { name, unterminated });
        }
        let n = c.usize()?;
        let mut segments = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let (offset, len) = (c.u64()?, c.u64()?);
            let stream = u32::try_from(c.u64()?).map_err(|_| Error::Corrupt("stream id"))?;
            if stream as usize >= streams.len() {
                return Err(Error::Corrupt("stream id"));
            }
            let (lines, raw_bytes) = (c.u64()?, c.u64()?);
            let time_range = match c.take(1)?[0] {
                0 => None,
                _ => Some((c.i64()?, c.i64()?)),
            };
            segments.push(SegmentInfo {
                offset,
                len,
                stream,
                lines,
                raw_bytes,
                time_range,
            });
        }
        if !c.is_empty() {
            return Err(Error::Corrupt("trailing footer bytes"));
        }
        Ok(Index { streams, segments })
    }
}

/// Finds the live footer. Returns the index and the byte offset where the
/// valid archive ends (just past its trailer).
fn read_index(file: &mut File) -> Result<(Index, u64)> {
    let size = file.seek(SeekFrom::End(0))?;
    let mut header = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)
        .map_err(|_| Error::Corrupt("not a logjar archive"))?;
    if &header != HEADER {
        return Err(Error::Corrupt("not a logjar archive"));
    }
    if let Some(found) = try_trailer(file, size)? {
        return Ok(found);
    }
    // Torn tail: walk back looking for an older trailer that verifies.
    // ponytail: linear scan over the whole file; fine for recovery, which is rare.
    let mut buf = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_end(&mut buf)?;
    let mut end = buf.len();
    while let Some(p) = buf[..end].windows(4).rposition(|w| w == TRAILER_MAGIC) {
        let candidate_end = (p + 4) as u64;
        if let Some(found) = try_trailer(file, candidate_end)? {
            return Ok(found);
        }
        end = p + 3;
    }
    Err(Error::Corrupt("no valid footer"))
}

fn try_trailer(file: &mut File, end: u64) -> Result<Option<(Index, u64)>> {
    if end < HEADER.len() as u64 + TRAILER_LEN {
        return Ok(None);
    }
    let mut t = [0u8; TRAILER_LEN as usize];
    file.seek(SeekFrom::Start(end - TRAILER_LEN))?;
    file.read_exact(&mut t)?;
    if &t[16..] != TRAILER_MAGIC {
        return Ok(None);
    }
    let off = u64::from_le_bytes(t[..8].try_into().unwrap());
    let len = u32::from_le_bytes(t[8..12].try_into().unwrap()) as u64;
    let crc = u32::from_le_bytes(t[12..16].try_into().unwrap());
    if off.checked_add(len) != Some(end - TRAILER_LEN) || off < HEADER.len() as u64 {
        return Ok(None);
    }
    let mut footer = vec![0u8; len as usize];
    file.seek(SeekFrom::Start(off))?;
    file.read_exact(&mut footer)?;
    if crc32fast::hash(&footer) != crc {
        return Ok(None);
    }
    let index = Index::decode(&footer)?;
    if index
        .segments
        .iter()
        .any(|s| s.offset.saturating_add(s.len) > off)
    {
        return Ok(None);
    }
    Ok(Some((index, end)))
}

/// Tuning knobs for writing.
#[derive(Debug, Clone)]
pub struct Options {
    /// zstd level for every block.
    pub level: i32,
    /// Close a segment after this many input bytes.
    pub segment_bytes: usize,
    /// Close a segment after this many lines.
    pub segment_lines: usize,
    /// Segments encoded in parallel.
    pub threads: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            level: 9,
            segment_bytes: 32 << 20,
            segment_lines: 1 << 20,
            threads: par::default_threads(),
        }
    }
}

/// Totals for one call to [`Writer::add_stream`].
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    pub lines: u64,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
    pub segments: u64,
}

/// Writes or appends to an archive. Nothing is visible to readers until
/// [`Writer::finish`] writes the footer.
pub struct Writer {
    file: File,
    pos: u64,
    index: Index,
    opts: Options,
}

impl Writer {
    /// Creates (or truncates) an archive.
    pub fn create(path: impl AsRef<Path>, opts: Options) -> Result<Writer> {
        let mut file = File::create(path)?;
        file.write_all(HEADER)?;
        Ok(Writer {
            file,
            pos: HEADER.len() as u64,
            index: Index::default(),
            opts,
        })
    }

    /// Opens an existing archive for appending. A torn tail from an earlier
    /// crash is truncated here.
    pub fn append(path: impl AsRef<Path>, opts: Options) -> Result<Writer> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let (index, end) = read_index(&mut file)?;
        file.set_len(end)?;
        file.seek(SeekFrom::Start(end))?;
        Ok(Writer {
            file,
            pos: end,
            index,
            opts,
        })
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Reads lines from `input` until EOF and adds them to the stream called
    /// `name`, creating it if needed. Appending to a stream continues it.
    pub fn add_stream(&mut self, name: &str, mut input: impl BufRead) -> Result<StreamStats> {
        let id = match self.index.streams.iter().position(|s| s.name == name) {
            Some(i) if self.index.streams[i].unterminated => {
                return Err(Error::Invalid(format!(
                    "cannot append to stream {name:?}: its last line has no newline"
                )))
            }
            Some(i) => i,
            None => {
                self.index.streams.push(StreamInfo {
                    name: name.to_string(),
                    unterminated: false,
                });
                self.index.streams.len() - 1
            }
        } as u32;

        let mut stats = StreamStats::default();
        let threads = self.opts.threads.max(1);
        let mut eof = false;
        // Read up to `threads` segment-sized chunks, encode them in
        // parallel, write them in order, repeat. Memory stays bounded at
        // roughly `threads` segments in flight.
        while !eof {
            let mut chunks = Vec::with_capacity(threads);
            while chunks.len() < threads {
                let (chunk, more) = read_chunk(&mut input, &self.opts)?;
                if !chunk.is_empty() {
                    chunks.push(chunk);
                }
                if !more {
                    eof = true;
                    break;
                }
            }
            let level = self.opts.level;
            let encoded = par::map(&chunks, threads, |chunk| {
                let mut b = Builder::new(id);
                let body = chunk.strip_suffix(b"\n").unwrap_or(chunk);
                body.split(|&c| c == b'\n').for_each(|line| b.push(line));
                b.finish(level)
            });
            if chunks.last().is_some_and(|c| c.last() != Some(&b'\n')) {
                self.index.streams[id as usize].unterminated = true;
            }
            for enc in encoded {
                self.write_segment(enc?, &mut stats)?;
            }
        }
        if self.index.streams[id as usize].unterminated {
            stats.raw_bytes -= 1;
            let last = self
                .index
                .segments
                .last_mut()
                .expect("unterminated implies a line");
            last.raw_bytes -= 1;
        }
        Ok(stats)
    }

    fn write_segment(&mut self, enc: segment::Encoded, stats: &mut StreamStats) -> Result<()> {
        self.file.write_all(&enc.bytes)?;
        let len = enc.bytes.len() as u64;
        self.index.segments.push(segment_info(&enc, self.pos));
        self.pos += len;
        stats.lines += enc.lines;
        stats.raw_bytes += enc.raw_bytes;
        stats.compressed_bytes += len;
        stats.segments += 1;
        Ok(())
    }

    /// Writes the footer and syncs. Returns the final index.
    pub fn finish(mut self) -> Result<Index> {
        let footer = self.index.encode();
        let mut tail = footer.clone();
        tail.extend_from_slice(&self.pos.to_le_bytes());
        tail.extend_from_slice(&(footer.len() as u32).to_le_bytes());
        tail.extend_from_slice(&crc32fast::hash(&footer).to_le_bytes());
        tail.extend_from_slice(TRAILER_MAGIC);
        self.file.write_all(&tail)?;
        self.file.sync_all()?;
        Ok(self.index)
    }
}

/// Reads whole lines (newlines kept) until the chunk reaches the segment
/// limits. Returns the chunk and whether more input may follow.
fn read_chunk(input: &mut impl BufRead, opts: &Options) -> Result<(Vec<u8>, bool)> {
    let mut chunk = Vec::new();
    let mut lines = 0;
    while chunk.len() < opts.segment_bytes && lines < opts.segment_lines {
        if input.read_until(b'\n', &mut chunk)? == 0 || chunk.last() != Some(&b'\n') {
            return Ok((chunk, false));
        }
        lines += 1;
    }
    Ok((chunk, true))
}

fn segment_info(enc: &segment::Encoded, offset: u64) -> SegmentInfo {
    SegmentInfo {
        offset,
        len: enc.bytes.len() as u64,
        stream: enc.stream,
        lines: enc.lines,
        raw_bytes: enc.raw_bytes,
        time_range: enc.time_range,
    }
}

/// A read-only handle on an archive.
pub struct Archive {
    file: Mutex<File>,
    index: Index,
    size: u64,
}

impl Archive {
    pub fn open(path: impl AsRef<Path>) -> Result<Archive> {
        let mut file = File::open(path)?;
        let (index, size) = read_index(&mut file)?;
        Ok(Archive {
            file: Mutex::new(file),
            index,
            size,
        })
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Bytes of the live archive (excluding any torn tail).
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn stream_id(&self, name: &str) -> Option<u32> {
        self.index
            .streams
            .iter()
            .position(|s| s.name == name)
            .map(|i| i as u32)
    }

    pub(crate) fn read_segment(&self, i: usize) -> Result<Segment> {
        let info = &self.index.segments[i];
        let mut buf =
            vec![0u8; usize::try_from(info.len).map_err(|_| Error::Corrupt("segment len"))?];
        {
            let mut f = self.file.lock().unwrap_or_else(|e| e.into_inner());
            f.seek(SeekFrom::Start(info.offset))?;
            f.read_exact(&mut buf)?;
        }
        Segment::parse(buf)
    }

    /// Writes the exact original bytes of one stream.
    pub fn write_stream(&self, stream: u32, out: &mut impl Write) -> Result<()> {
        let mut r = self.stream_reader(stream)?;
        // Decode errors travel through io::copy wrapped in io::Error; unwrap
        // them so callers still see Error::Corrupt rather than Error::Io.
        std::io::copy(&mut r, out).map_err(|e| {
            if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
                *e.into_inner().unwrap().downcast::<Error>().unwrap()
            } else {
                Error::Io(e)
            }
        })?;
        Ok(())
    }

    /// The original bytes of one stream as a reader, decoded one segment
    /// at a time.
    pub fn stream_reader(&self, stream: u32) -> Result<StreamReader<'_>> {
        let info = self
            .index
            .streams
            .get(stream as usize)
            .ok_or_else(|| Error::Invalid("no such stream".into()))?;
        let segs: Vec<usize> = (0..self.index.segments.len())
            .filter(|&i| self.index.segments[i].stream == stream)
            .collect();
        Ok(StreamReader {
            archive: self,
            segs,
            next: 0,
            buf: Vec::new(),
            pos: 0,
            unterminated: info.unterminated,
        })
    }
}

/// Reads a stream's original bytes. See [`Archive::stream_reader`].
pub struct StreamReader<'a> {
    archive: &'a Archive,
    segs: Vec<usize>,
    next: usize,
    buf: Vec<u8>,
    pos: usize,
    unterminated: bool,
}

impl StreamReader<'_> {
    fn refill(&mut self) -> Result<()> {
        self.buf.clear();
        self.pos = 0;
        let Some(&i) = self.segs.get(self.next) else {
            return Ok(());
        };
        self.next += 1;
        let seg = self.archive.read_segment(i)?;
        let lines = self.archive.index.segments[i].lines as usize;
        let buf = &mut self.buf;
        segment::decode_all(&seg, lines, |line| {
            buf.extend_from_slice(line);
            buf.push(b'\n');
            Ok(())
        })?;
        if self.unterminated && self.next == self.segs.len() {
            self.buf.pop();
        }
        Ok(())
    }
}

impl Read for StreamReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.fill_buf()?.len().min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl BufRead for StreamReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        while self.pos >= self.buf.len() && self.next < self.segs.len() {
            self.refill().map_err(std::io::Error::other)?;
        }
        Ok(&self.buf[self.pos.min(self.buf.len())..])
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("logjar-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn unpack(a: &Archive, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        a.write_stream(a.stream_id(name).unwrap(), &mut out)
            .unwrap();
        out
    }

    #[test]
    fn create_append_read() {
        let p = tmp("basic.ljar");
        let small = Options {
            segment_lines: 2,
            ..Options::default()
        };
        let mut w = Writer::create(&p, small.clone()).unwrap();
        w.add_stream("a.log", &b"one 1\ntwo 2\nthree 3\n"[..])
            .unwrap();
        w.add_stream("b.log", &b"no newline at end 42"[..]).unwrap();
        w.finish().unwrap();

        let mut w = Writer::append(&p, small).unwrap();
        w.add_stream("a.log", &b"four 4\n"[..]).unwrap();
        assert!(w.add_stream("b.log", &b"more\n"[..]).is_err());
        w.finish().unwrap();

        let a = Archive::open(&p).unwrap();
        assert_eq!(unpack(&a, "a.log"), b"one 1\ntwo 2\nthree 3\nfour 4\n");
        assert_eq!(unpack(&a, "b.log"), b"no newline at end 42");
        assert_eq!(a.index().segments.len(), 4);
    }

    #[test]
    fn torn_tail_recovers_previous_footer() {
        let p = tmp("torn.ljar");
        let mut w = Writer::create(&p, Options::default()).unwrap();
        w.add_stream("x", &b"alpha 1\n"[..]).unwrap();
        w.finish().unwrap();
        let good = std::fs::metadata(&p).unwrap().len();
        // Simulate a crash halfway through an append: garbage after the footer.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"\x28\xb5\x2f\xfd half a segment LJF1 junk")
            .unwrap();
        drop(f);

        let a = Archive::open(&p).unwrap();
        assert_eq!(a.size(), good);
        assert_eq!(unpack(&a, "x"), b"alpha 1\n");
        drop(a);

        let mut w = Writer::append(&p, Options::default()).unwrap();
        w.add_stream("x", &b"beta 2\n"[..]).unwrap();
        w.finish().unwrap();
        let a = Archive::open(&p).unwrap();
        assert_eq!(unpack(&a, "x"), b"alpha 1\nbeta 2\n");
    }

    #[test]
    fn rejects_non_archives() {
        let p = tmp("notes.txt");
        std::fs::write(&p, b"just a text file").unwrap();
        assert!(matches!(Archive::open(&p), Err(Error::Corrupt(_))));
    }
}
