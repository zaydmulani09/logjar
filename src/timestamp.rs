//! Leading-timestamp detection with verified round trips.
//!
//! A timestamp format is a small spec string (`%Y-%m-%d %H:%M:%S,%3`). The
//! detector tries the built-in specs at the start of a line; a match is only
//! accepted if formatting the parsed value with the same spec reproduces the
//! exact input bytes. That check is what keeps extraction lossless: a wrong
//! weekday, a leap second or an odd padding simply stays in the message.
//!
//! Values are stored in the spec's native unit (seconds scaled by its
//! fraction digits) so millisecond logs delta-encode into small integers.
//! The spec strings themselves are written into each segment, so adding a
//! new built-in never changes how old archives decode.
//!
//! Times carry no zone: they are compared as UTC. Specs without a year
//! (syslog's `Jun 14 15:16:01`) decode as 1970 and are ignored by time
//! filters.

use std::sync::OnceLock;

use crate::{Error, Result};

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const WEEKDAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

#[derive(Debug, Clone)]
pub struct Spec {
    pub text: String,
    pub frac: u32,
    pub has_year: bool,
}

impl Spec {
    pub fn new(text: impl Into<String>) -> Spec {
        let text = text.into();
        let frac = if text.contains("%9") {
            9
        } else if text.contains("%6") {
            6
        } else if text.contains("%3") {
            3
        } else {
            0
        };
        let has_year = text.contains("%Y") || text.contains("%y");
        Spec {
            text,
            frac,
            has_year,
        }
    }

    /// Native value to nanoseconds since the epoch.
    pub fn to_nanos(&self, value: i64) -> i64 {
        value.saturating_mul(10i64.pow(9 - self.frac))
    }
}

/// The built-in formats, longest variants first so `,%3` beats a bare `%S`.
pub fn builtin() -> &'static [Spec] {
    static SPECS: OnceLock<Vec<Spec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let mut v = Vec::new();
        for bracket in [false, true] {
            for sep in ["T", " "] {
                for frac in [".%9", ".%6", ".%3", ",%3", ""] {
                    for zone in ["Z", ""] {
                        let s = format!("%Y-%m-%d{sep}%H:%M:%S{frac}{zone}");
                        v.push(Spec::new(if bracket { format!("[{s}]") } else { s }));
                    }
                }
            }
        }
        for s in [
            "%y%m%d %H%M%S",
            "%y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y%m%d-%H:%M:%S:%3",
            "[%a %b %d %H:%M:%S %Y]",
            "%a %b %d %H:%M:%S %Y",
            "%b %e %H:%M:%S",
            "%m-%d %H:%M:%S.%3",
            "[%m.%d %H:%M:%S]",
        ] {
            v.push(Spec::new(s));
        }
        v
    })
}

// Howard Hinnant's civil-from-days algorithms, proleptic Gregorian.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

fn digits(input: &[u8], pos: &mut usize, n: usize, space_pad: bool) -> Option<i64> {
    let s = input.get(*pos..*pos + n)?;
    let mut v = 0i64;
    for (i, &b) in s.iter().enumerate() {
        if b == b' ' && space_pad && i + 1 < n {
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as i64;
    }
    *pos += n;
    Some(v)
}

fn word(input: &[u8], pos: &mut usize, table: &[&[u8; 3]]) -> Option<usize> {
    let s = input.get(*pos..*pos + 3)?;
    let i = table.iter().position(|w| &w[..] == s)?;
    *pos += 3;
    Some(i)
}

/// Parses `spec` at the start of `input`; returns the native value and the
/// number of bytes consumed. Does not verify; see [`detect_with`].
pub fn parse(spec: &Spec, input: &[u8]) -> Option<(i64, usize)> {
    let (mut y, mut mo, mut d, mut h, mut mi, mut s, mut f) = (1970i64, 1, 1, 0, 0, 0, 0i64);
    let sp = spec.text.as_bytes();
    let (mut i, mut pos) = (0, 0);
    while i < sp.len() {
        if sp[i] != b'%' {
            if input.get(pos) != Some(&sp[i]) {
                return None;
            }
            i += 1;
            pos += 1;
            continue;
        }
        let code = *sp.get(i + 1)?;
        i += 2;
        match code {
            b'Y' => y = digits(input, &mut pos, 4, false)?,
            b'y' => {
                let v = digits(input, &mut pos, 2, false)?;
                y = if v < 70 { 2000 + v } else { 1900 + v };
            }
            b'm' => mo = digits(input, &mut pos, 2, false)?,
            b'd' => d = digits(input, &mut pos, 2, false)?,
            b'e' => d = digits(input, &mut pos, 2, true)?,
            b'H' => h = digits(input, &mut pos, 2, false)?,
            b'M' => mi = digits(input, &mut pos, 2, false)?,
            b'S' => s = digits(input, &mut pos, 2, false)?,
            b'b' => mo = word(input, &mut pos, &MONTHS)? as i64 + 1,
            b'a' => {
                word(input, &mut pos, &WEEKDAYS)?;
            }
            b'3' | b'6' | b'9' => f = digits(input, &mut pos, (code - b'0') as usize, false)?,
            _ => return None,
        }
    }
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86400 + h * 3600 + mi * 60 + s;
    Some((secs * 10i64.pow(spec.frac) + f, pos))
}

/// Writes `value` in `spec`'s format.
pub fn format(spec: &Spec, value: i64, out: &mut Vec<u8>) -> Result<()> {
    let scale = 10i64.pow(spec.frac);
    let (secs, f) = (value.div_euclid(scale), value.rem_euclid(scale));
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    let sp = spec.text.as_bytes();
    let mut i = 0;
    while i < sp.len() {
        if sp[i] != b'%' {
            out.push(sp[i]);
            i += 1;
            continue;
        }
        let code = *sp.get(i + 1).ok_or(Error::Corrupt("timestamp spec"))?;
        i += 2;
        match code {
            b'Y' if (0..=9999).contains(&y) => write_num(out, y, 4, b'0'),
            b'Y' => return Err(Error::Corrupt("timestamp year out of range")),
            b'y' => write_num(out, y.rem_euclid(100), 2, b'0'),
            b'm' => write_num(out, mo as i64, 2, b'0'),
            b'd' => write_num(out, d as i64, 2, b'0'),
            b'e' => write_num(out, d as i64, 2, b' '),
            b'H' => write_num(out, tod / 3600, 2, b'0'),
            b'M' => write_num(out, tod / 60 % 60, 2, b'0'),
            b'S' => write_num(out, tod % 60, 2, b'0'),
            b'b' => out.extend_from_slice(MONTHS[mo as usize - 1]),
            b'a' => out.extend_from_slice(WEEKDAYS[(days + 4).rem_euclid(7) as usize]),
            b'3' | b'6' | b'9' => write_num(out, f, (code - b'0') as usize, b'0'),
            _ => return Err(Error::Corrupt("timestamp spec")),
        };
    }
    Ok(())
}

fn write_num(out: &mut Vec<u8>, v: i64, width: usize, pad: u8) {
    let s = v.to_string();
    for _ in s.len()..width {
        out.push(pad);
    }
    out.extend_from_slice(s.as_bytes());
}

/// Finds a verified leading timestamp. Tries `hint` first (the index that
/// matched the previous line) because consecutive lines almost always share
/// a format. Returns `(spec index, value, length)`.
pub fn detect_with(specs: &[Spec], hint: usize, line: &[u8]) -> Option<(usize, i64, usize)> {
    let first = *line.first()?;
    if !(first.is_ascii_digit() || first == b'[' || first.is_ascii_uppercase()) {
        return None;
    }
    let order = std::iter::once(hint).chain((0..specs.len()).filter(|&i| i != hint));
    let mut buf = Vec::with_capacity(32);
    for i in order {
        let Some(spec) = specs.get(i) else { continue };
        if let Some((v, n)) = parse(spec, line) {
            buf.clear();
            if format(spec, v, &mut buf).is_ok() && buf == line[..n] {
                return Some((i, v, n));
            }
        }
    }
    None
}

/// Parses a user-supplied time bound (`--after 2015-10-18T18:01`) into
/// nanoseconds since the epoch. Accepts dates, ISO date-times with optional
/// seconds/fractions/`Z`, and raw epoch seconds.
pub fn parse_bound(s: &str) -> Option<i64> {
    let s = s.trim();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.len() > 8 {
        return s.parse::<i64>().ok()?.checked_mul(1_000_000_000);
    }
    let extra = ["%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"].map(Spec::new);
    builtin()
        .iter()
        .chain(extra.iter())
        .filter(|sp| sp.has_year)
        .find_map(|sp| match parse(sp, s.as_bytes()) {
            Some((v, n)) if n == s.len() => Some(sp.to_nanos(v)),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(line: &str) -> Option<(String, usize)> {
        detect_with(builtin(), 0, line.as_bytes()).map(|(i, _, n)| (builtin()[i].text.clone(), n))
    }

    #[test]
    fn civil_roundtrip() {
        for z in [-800_000i64, -1, 0, 1, 10_957, 19_000, 2_932_896] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn real_formats() {
        let cases = [
            ("2015-10-18 18:01:47,978 INFO", "%Y-%m-%d %H:%M:%S,%3"),
            ("081109 203615 148 INFO dfs.DataNode", "%y%m%d %H%M%S"),
            ("17/06/09 20:10:40 INFO executor", "%y/%m/%d %H:%M:%S"),
            (
                "[Sun Dec 04 04:47:44 2005] [notice]",
                "[%a %b %d %H:%M:%S %Y]",
            ),
            ("Jun 14 15:16:01 combo sshd", "%b %e %H:%M:%S"),
            ("Jun  9 06:06:20 combo syslogd", "%b %e %H:%M:%S"),
            (
                "03-17 16:13:38.811  1702  2395 D Window",
                "%m-%d %H:%M:%S.%3",
            ),
            ("20171223-22:15:29:606|Step_LSC", "%Y%m%d-%H:%M:%S:%3"),
            ("2024-01-15T10:20:30.123456Z GET /", "%Y-%m-%dT%H:%M:%S.%6Z"),
            ("[10.30 16:49:06] chrome.exe", "[%m.%d %H:%M:%S]"),
        ];
        for (line, want) in cases {
            let (spec, n) = detect(line).unwrap_or_else(|| panic!("no match: {line}"));
            assert_eq!(spec, want, "{line}");
            let mut out = Vec::new();
            let sp = Spec::new(spec);
            let (v, _) = parse(&sp, line.as_bytes()).unwrap();
            format(&sp, v, &mut out).unwrap();
            assert_eq!(&out[..], &line.as_bytes()[..n]);
        }
    }

    #[test]
    fn rejects_unverifiable() {
        // Wrong weekday for that date, leap second, bad month.
        assert!(detect("[Mon Dec 04 04:47:44 2005] x").is_none());
        assert!(detect("2016-12-31 23:59:60 x").is_none());
        assert!(detect("2016-13-01 00:00:00 x").is_none());
        assert!(detect("Feb 30 10:00:00 x").is_none());
        assert!(detect("hello").is_none());
    }

    #[test]
    fn bounds() {
        let a = parse_bound("2015-10-18").unwrap();
        let b = parse_bound("2015-10-18T00:00:00Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            parse_bound("2015-10-18 18:01").unwrap() - a,
            (18 * 3600 + 60) * 1_000_000_000
        );
        assert_eq!(
            parse_bound("1445191307").unwrap(),
            1_445_191_307_000_000_000
        );
        assert!(parse_bound("yesterday").is_none());
    }
}
