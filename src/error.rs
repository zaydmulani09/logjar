use std::fmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The archive bytes are not what logjar wrote (bad magic, checksum,
    /// truncated block...). Carries a short static reason.
    Corrupt(&'static str),
    /// A search query that could not be parsed.
    Query(String),
    /// A caller mistake: unknown stream, appending after an unterminated line...
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Corrupt(why) => write!(f, "corrupt archive: {why}"),
            Error::Query(why) => write!(f, "bad query: {why}"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
