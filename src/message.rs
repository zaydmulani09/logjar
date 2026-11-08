//! Splitting one log message into a *template* (the static text, with
//! placeholders where variables were) and the *variables* themselves.
//!
//! ```text
//! "Received block blk_-1608 of size 67108864 from /10.251.73.220"
//!   template: "Received block \x13 of size \x11 from /\x13"
//!   vars:     [Dict("blk_-1608"), Int(67108864), Dict("10.251.73.220")]
//! ```
//!
//! A token is a maximal run of non-delimiter bytes. Tokens without an ASCII
//! digit are static text. Tokens with a digit are variables: canonical
//! integers and decimals are encoded inline, anything else goes to the
//! segment's variable dictionary. The encoding is exact for arbitrary bytes:
//! `decode(encode(m)) == m` always, which the tests below fuzz.

use crate::{Error, Result};

/// Placeholder bytes inside a template. They are control characters, so they
/// are always delimiters and never inside a token; literal occurrences in the
/// input are escaped with [`ESC`].
pub const PH_INT: u8 = 0x11;
pub const PH_FLOAT: u8 = 0x12;
pub const PH_DICT: u8 = 0x13;
pub const ESC: u8 = 0x14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Int,
    Float,
    Dict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Var<'a> {
    Int(i64),
    /// Digits as an integer plus `meta` = digit count, fraction digits, sign.
    Float(u64, u64),
    Dict(&'a [u8]),
}

/// Whitespace, control bytes and ASCII punctuation except `. - _ +` split
/// tokens. Keeping `.` and `-` inside tokens keeps IPs, decimals, negative
/// numbers and UUIDs whole.
#[inline]
pub fn is_delim(b: u8) -> bool {
    b <= b' ' || b == 0x7f || (b.is_ascii_punctuation() && !matches!(b, b'.' | b'-' | b'_' | b'+'))
}

/// `-?(0|[1-9][0-9]*)` that fits an i64. `-0` is excluded: it would decode
/// as `0`.
pub fn parse_int(tok: &[u8]) -> Option<i64> {
    let digits = tok.strip_prefix(b"-").unwrap_or(tok);
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits[0] == b'0' && (digits.len() > 1 || tok.len() > 1) {
        return None;
    }
    // Safe: all ASCII digits. Fails only on i64 overflow.
    std::str::from_utf8(tok).ok()?.parse().ok()
}

/// `-?[0-9]+\.[0-9]+` with at most 19 digits in total. Leading and trailing
/// zeros survive because the digit count is part of the encoding.
pub fn encode_float(tok: &[u8]) -> Option<(u64, u64)> {
    let (neg, body) = match tok.strip_prefix(b"-") {
        Some(b) => (1u64, b),
        None => (0, tok),
    };
    let dot = body.iter().position(|&b| b == b'.')?;
    let (int, frac) = (&body[..dot], &body[dot + 1..]);
    let digits = int.len() + frac.len();
    if int.is_empty() || frac.is_empty() || digits > 19 {
        return None;
    }
    let mut v = 0u64;
    for &b in int.iter().chain(frac) {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some((v, (digits as u64) << 6 | (frac.len() as u64) << 1 | neg))
}

pub fn decode_float(value: u64, meta: u64, out: &mut Vec<u8>) -> Result<()> {
    let digits = (meta >> 6) as usize;
    let frac = ((meta >> 1) & 0x1f) as usize;
    if digits > 19 || frac == 0 || frac >= digits {
        return Err(Error::Corrupt("float meta"));
    }
    if meta & 1 == 1 {
        out.push(b'-');
    }
    let s = format!("{value:0digits$}");
    if s.len() != digits {
        return Err(Error::Corrupt("float digits"));
    }
    out.extend_from_slice(&s.as_bytes()[..digits - frac]);
    out.push(b'.');
    out.extend_from_slice(&s.as_bytes()[digits - frac..]);
    Ok(())
}

pub fn classify(tok: &[u8]) -> Option<Var<'_>> {
    if !tok.iter().any(u8::is_ascii_digit) {
        return None;
    }
    if let Some(i) = parse_int(tok) {
        return Some(Var::Int(i));
    }
    if let Some((v, m)) = encode_float(tok) {
        return Some(Var::Float(v, m));
    }
    Some(Var::Dict(tok))
}

/// Calls `f(run, is_delimiter_run)` for each maximal run of the message.
pub fn for_each_token<'a>(msg: &'a [u8], mut f: impl FnMut(&'a [u8], bool)) {
    let mut i = 0;
    while i < msg.len() {
        let d = is_delim(msg[i]);
        let start = i;
        while i < msg.len() && is_delim(msg[i]) == d {
            i += 1;
        }
        f(&msg[start..i], d);
    }
}

fn push_literal(tpl: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        if (PH_INT..=ESC).contains(&b) {
            tpl.push(ESC);
        }
        tpl.push(b);
    }
}

/// Appends the template of `msg` to `tpl` and its variables to `vars`.
pub fn encode<'a>(msg: &'a [u8], tpl: &mut Vec<u8>, vars: &mut Vec<Var<'a>>) {
    for_each_token(msg, |run, delim| {
        if delim {
            push_literal(tpl, run);
            return;
        }
        match classify(run) {
            None => push_literal(tpl, run),
            Some(v) => {
                tpl.push(match v {
                    Var::Int(_) => PH_INT,
                    Var::Float(..) => PH_FLOAT,
                    Var::Dict(_) => PH_DICT,
                });
                vars.push(v);
            }
        }
    });
}

/// One element of a parsed template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Text(Vec<u8>),
    Var(Kind),
}

/// Splits template bytes into literal text and placeholders, undoing escapes.
pub fn pieces(tpl: &[u8]) -> Result<Vec<Piece>> {
    let mut out = Vec::new();
    let mut text = Vec::new();
    let mut i = 0;
    while i < tpl.len() {
        let kind = match tpl[i] {
            PH_INT => Kind::Int,
            PH_FLOAT => Kind::Float,
            PH_DICT => Kind::Dict,
            ESC => {
                text.push(*tpl.get(i + 1).ok_or(Error::Corrupt("dangling escape"))?);
                i += 2;
                continue;
            }
            b => {
                text.push(b);
                i += 1;
                continue;
            }
        };
        if !text.is_empty() {
            out.push(Piece::Text(std::mem::take(&mut text)));
        }
        out.push(Piece::Var(kind));
        i += 1;
    }
    if !text.is_empty() {
        out.push(Piece::Text(text));
    }
    Ok(out)
}

/// Number of variables per kind a template needs, in order.
pub fn slots(tpl: &[u8]) -> Result<Vec<Kind>> {
    Ok(pieces(tpl)?
        .into_iter()
        .filter_map(|p| match p {
            Piece::Var(k) => Some(k),
            Piece::Text(_) => None,
        })
        .collect())
}

/// Renders a template for humans: `Received block <var> of size <int>`.
pub fn render(tpl: &[u8]) -> Result<String> {
    let mut s = String::new();
    for p in pieces(tpl)? {
        match p {
            Piece::Text(t) => s.push_str(&String::from_utf8_lossy(&t)),
            Piece::Var(Kind::Int) => s.push_str("<int>"),
            Piece::Var(Kind::Float) => s.push_str("<float>"),
            Piece::Var(Kind::Dict) => s.push_str("<var>"),
        }
    }
    Ok(s)
}

/// Writes a variable's original text.
pub fn write_var(v: &Var<'_>, out: &mut Vec<u8>) -> Result<()> {
    match *v {
        Var::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Var::Float(value, meta) => decode_float(value, meta, out)?,
        Var::Dict(d) => out.extend_from_slice(d),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &[u8]) {
        let (mut tpl, mut vars) = (Vec::new(), Vec::new());
        encode(msg, &mut tpl, &mut vars);
        let mut out = Vec::new();
        let mut it = vars.iter();
        for p in pieces(&tpl).unwrap() {
            match p {
                Piece::Text(t) => out.extend_from_slice(&t),
                Piece::Var(k) => {
                    let v = it.next().expect("enough vars");
                    assert_eq!(
                        k,
                        match v {
                            Var::Int(_) => Kind::Int,
                            Var::Float(..) => Kind::Float,
                            Var::Dict(_) => Kind::Dict,
                        }
                    );
                    write_var(v, &mut out).unwrap();
                }
            }
        }
        assert!(it.next().is_none());
        assert_eq!(out, msg, "roundtrip of {:?}", String::from_utf8_lossy(msg));
    }

    #[test]
    fn hdfs_line() {
        let msg = b"Received block blk_-1608999687919862906 of size 67108864 from /10.250.19.102";
        let (mut tpl, mut vars) = (Vec::new(), Vec::new());
        encode(msg, &mut tpl, &mut vars);
        assert_eq!(
            render(&tpl).unwrap(),
            "Received block <var> of size <int> from /<var>"
        );
        assert_eq!(vars[1], Var::Int(67108864));
        roundtrip(msg);
    }

    #[test]
    fn number_shapes() {
        for s in [
            "0",
            "-0",
            "007",
            "-1",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "1.5",
            "-0.050",
            "00.10",
            "1.",
            ".5",
            "1.2.3",
            "1234567890.123456789",
            "12345678901234567890.1",
            "-",
            "0x7fff",
            "3e10",
        ] {
            roundtrip(s.as_bytes());
        }
        assert_eq!(classify(b"-0"), Some(Var::Dict(b"-0")));
        assert!(matches!(classify(b"-0.050"), Some(Var::Float(..))));
        assert_eq!(
            classify(b"9223372036854775808"),
            Some(Var::Dict(b"9223372036854775808"))
        );
    }

    #[test]
    fn placeholder_bytes_in_input_are_escaped() {
        roundtrip(b"a\x11b\x12 \x13\x14 12 \x14");
        roundtrip(b"\x14");
    }

    #[test]
    fn random_bytes_roundtrip() {
        let mut s = 0x9e3779b97f4a7c15u64;
        for _ in 0..2000 {
            let mut msg = Vec::new();
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let len = (s % 64) as usize;
            for _ in 0..len {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                // Bias toward digits, dots, dashes and spaces.
                let b = match s % 6 {
                    0 => b"0123456789"[(s >> 8) as usize % 10],
                    1 => b".-_ :/"[(s >> 8) as usize % 6],
                    _ => (s >> 16) as u8,
                };
                msg.push(b);
            }
            roundtrip(&msg);
        }
    }
}
