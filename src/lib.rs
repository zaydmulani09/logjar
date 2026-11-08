//! logjar: searchable compressed log archives.

mod archive;
mod error;
mod message;
mod query;
mod segment;
mod timestamp;
mod varint;

pub use archive::{Archive, Index, Options, SegmentInfo, StreamInfo, StreamStats, Writer};
pub use error::{Error, Result};
pub use query::Query;
