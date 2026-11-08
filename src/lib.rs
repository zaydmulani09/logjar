//! # logjar
//!
//! Searchable compressed log archives.
//!
//! logjar splits every log line into a *template* (its static text) and
//! *variables* (the numbers, ids and addresses that change), stores them in
//! columnar, zstd-compressed segments, and searches the result without
//! decompressing it whole. Before touching any line, a search proves which
//! templates cannot possibly match by running the query's automaton over the
//! template symbolically, so selective queries skip almost everything.
//!
//! Archives are lossless: decoding returns the input byte for byte,
//! including CRLF line endings, invalid UTF-8 and a missing final newline.
//!
//! ```
//! use logjar::{Archive, Options, Query, Writer};
//!
//! # fn main() -> logjar::Result<()> {
//! # let path = std::env::temp_dir().join(format!("logjar-doc-{}.ljar", std::process::id()));
//! let log = "\
//! 2015-10-18 18:01:47,978 INFO  [main] Created MRAppMaster for appattempt_1445144423722_0020_000001
//! 2015-10-18 18:05:12,100 ERROR [RMCommunicator] Failed to contact 10.86.169.121:8030 after 3 retries
//! 2015-10-18 18:09:30,001 WARN  [main] Slow GC pause 412.7 ms
//! ";
//!
//! // Write: one archive can hold many named streams (files).
//! let mut w = Writer::create(&path, Options::default())?;
//! w.add_stream("app.log", log.as_bytes())?;
//! w.finish()?;
//!
//! // Search: a glob matched anywhere in the line, optionally time-bounded.
//! let archive = Archive::open(&path)?;
//! let q = Query::new("Failed*retries")?.after(Query::parse_time("2015-10-18T18:00")?);
//! let mut hits = Vec::new();
//! archive.search(&q, &[], |m| {
//!     hits.push((m.line_number, String::from_utf8_lossy(&m.line).into_owned()));
//!     true // keep going
//! })?;
//! assert_eq!(hits.len(), 1);
//! assert_eq!(hits[0].0, 2);
//!
//! // Read back the exact original bytes.
//! let mut out = Vec::new();
//! archive.write_stream(archive.stream_id("app.log").unwrap(), &mut out)?;
//! assert_eq!(out, log.as_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! See `docs/FORMAT.md` for the on-disk layout and `docs/DESIGN.md` for how
//! template pruning works.

#![warn(missing_docs)]

mod archive;
mod error;
mod message;
mod par;
mod query;
mod regex;
mod search;
mod segment;
mod timestamp;
mod varint;

pub use archive::{
    Archive, Index, Options, SegmentInfo, StreamInfo, StreamReader, StreamStats, Writer,
};
pub use error::{Error, Result};
pub use query::Query;
pub use search::{ArchiveStats, Match, SearchStats};
