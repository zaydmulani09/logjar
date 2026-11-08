//! Baseline for benchmarks: compress a file with plain zstd (same library
//! and version logjar uses) and print the compressed size in bytes.
//!
//!     cargo run --release --example zstd_size -- <file> <level>

use std::io::{self, BufReader, Write};

struct Count(u64);

impl Write for Count {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: zstd_size <file> <level>");
    let level: i32 = args.next().map_or(19, |l| l.parse().expect("level"));
    let mut input = BufReader::new(std::fs::File::open(path)?);
    let mut enc = zstd::Encoder::new(Count(0), level)?;
    io::copy(&mut input, &mut enc)?;
    println!("{}", enc.finish()?.0);
    Ok(())
}
