//! LEB128 varints and zigzag mapping. Every integer column in a segment is a
//! stream of these before it goes to zstd.

use crate::{Error, Result};

pub fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, zigzag(v));
}

pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}

#[inline]
pub fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

#[inline]
pub fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// A forward cursor over a byte slice. All reads are bounds-checked and
/// return `Error::Corrupt` instead of panicking on truncated input.
#[derive(Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn u64(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or(Error::Corrupt("truncated varint"))?;
            self.pos += 1;
            if shift == 63 && b > 1 {
                return Err(Error::Corrupt("varint overflow"));
            }
            v |= ((b & 0x7f) as u64) << shift;
            if b < 0x80 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                return Err(Error::Corrupt("varint overflow"));
            }
        }
    }

    pub fn i64(&mut self) -> Result<i64> {
        self.u64().map(unzigzag)
    }

    pub fn usize(&mut self) -> Result<usize> {
        usize::try_from(self.u64()?).map_err(|_| Error::Corrupt("length overflow"))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(Error::Corrupt("truncated block"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.usize()?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_edges() {
        let vals = [0, 1, -1, 63, -64, 64, i64::MAX, i64::MIN, 300, -300];
        let mut buf = Vec::new();
        for &v in &vals {
            put_i64(&mut buf, v);
        }
        put_u64(&mut buf, u64::MAX);
        let mut c = Cursor::new(&buf);
        for &v in &vals {
            assert_eq!(c.i64().unwrap(), v);
        }
        assert_eq!(c.u64().unwrap(), u64::MAX);
        assert!(c.is_empty());
    }

    #[test]
    fn truncated_is_error_not_panic() {
        let mut c = Cursor::new(&[0x80, 0x80]);
        assert!(c.u64().is_err());
        let mut c = Cursor::new(&[5, 1, 2]);
        assert!(c.bytes().is_err());
        let mut c = Cursor::new(&[0xff; 11]);
        assert!(c.u64().is_err());
    }
}
