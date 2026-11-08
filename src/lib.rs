//! logjar: searchable compressed log archives.

mod archive;
mod error;
mod message;
mod par;
mod query;
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
