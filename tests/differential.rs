//! Randomized differential test: for generated logs of many shapes, every
//! search must return exactly what a naive scan over the original text
//! returns, and every stream must decode to its original bytes.

use logjar::{Archive, Options, Query, Writer};

/// A generated line and its true timestamp.
type Line = (String, Option<i64>);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

/// A generated line and the timestamp a correct parser must find in it
/// (nanoseconds; `None` when absent or yearless).
fn line(r: &mut Rng, t: &mut i64) -> (String, Option<i64>) {
    *t += r.below(5000) as i64;
    let secs = *t / 1000;
    let (h, m, s, ms) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60, *t % 1000);
    let day = 10 + (secs / 86400) % 18;
    let day_start = 1_614_556_800 + (day - 1) * 86_400; // 2021-03-{day} 00:00 UTC
    let tod = h * 3600 + m * 60 + s;
    let (ts, ns) = match r.below(6) {
        0 => (
            format!("2021-03-{day} {h:02}:{m:02}:{s:02},{ms:03} "),
            Some((day_start + tod) * 1_000_000_000 + ms * 1_000_000),
        ),
        1 => (
            format!("2021-03-{day}T{h:02}:{m:02}:{s:02}.{ms:03}Z "),
            Some((day_start + tod) * 1_000_000_000 + ms * 1_000_000),
        ),
        2 => (format!("Mar {day} {h:02}:{m:02}:{s:02} "), None),
        3 => (
            format!("210312 {h:02}{m:02}{s:02} "),
            Some((1_615_507_200 + tod) * 1_000_000_000),
        ),
        _ => (String::new(), None),
    };
    let level = r.pick(&["INFO", "WARN", "ERROR", "DEBUG", "info"]);
    let body = match r.below(9) {
        0 => format!(
            "Received block blk_{} of size {} from /10.{}.{}.{}",
            r.next() as i64 >> r.below(40),
            1u64 << r.below(30),
            r.below(256),
            r.below(256),
            r.below(256)
        ),
        1 => format!(
            "user={} action={} latency={}.{:03}ms ok={}",
            r.pick(&["alice", "bob", "u42", "svc-7"]),
            r.pick(&["GET", "PUT", "del"]),
            r.below(900),
            r.below(1000),
            r.below(2) == 0
        ),
        2 => format!(
            "java.lang.IllegalStateException: index {} out of bounds for length {}",
            r.below(100),
            r.below(100)
        ),
        3 => format!("\tat com.example.Worker.run(Worker.java:{})", r.below(500)),
        4 => format!(
            "temp={}.{} delta=-{}.{} id=0x{:x} uuid={:08x}-{:04x}",
            r.below(120),
            r.below(10),
            r.below(5),
            r.below(100),
            r.next() % 65536,
            r.next() as u32,
            r.next() as u16
        ),
        5 => format!(
            "weird bytes \u{1}\u{11}\u{14} {} ü€ {}",
            r.below(10),
            r.pick(&["007", "-0", "1.", ".5", "1e9", "--1"])
        ),
        6 => String::new(),
        7 => format!(
            "{} {} {}",
            r.pick(&["a", "b", "c"]),
            r.below(3),
            r.pick(&["x1", "y2", "z"])
        ),
        _ => format!(
            "PacketResponder {} for block blk_{} terminating",
            r.below(3),
            r.below(1_000_000)
        ),
    };
    (format!("{ts}{level} {body}"), ns)
}

/// The oracle: plain glob over every line, plus the time window checked
/// against the generator's own timestamps.
fn naive(lines: &[(String, Option<i64>)], q: &Query, window: Option<(i64, i64)>) -> Vec<u64> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, (l, ns))| {
            q.is_match(l.as_bytes())
                && window.is_none_or(|(lo, hi)| ns.is_some_and(|n| n >= lo && n < hi))
        })
        .map(|(i, _)| i as u64 + 1)
        .collect()
}

fn random_query(r: &mut Rng, lines: &[&str]) -> String {
    let l = lines[r.below(lines.len())];
    let chars: Vec<char> = l.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let a = r.below(chars.len());
    let b = (a + 1 + r.below(12)).min(chars.len());
    let mut q: String = chars[a..b].iter().collect();
    q = q
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?");
    match r.below(5) {
        0 if q.len() > 2 => {
            let k = q.char_indices().nth(1).map_or(1, |(i, _)| i);
            q.insert(k, '*');
        }
        1 => q.push('?'),
        2 => q = q.to_uppercase(),
        _ => {}
    }
    q
}

/// A regex built from a real line: a substring with metacharacters
/// escaped, then digit runs, letter runs, gaps and alternatives generalized.
fn random_regex(r: &mut Rng, lines: &[&str]) -> String {
    let l = lines[r.below(lines.len())].trim_end_matches('\r');
    let chars: Vec<char> = l.chars().collect();
    if chars.is_empty() {
        return "x".into();
    }
    let a = r.below(chars.len());
    let b = (a + 1 + r.below(16)).min(chars.len());
    let mut q = String::new();
    if a == 0 && r.below(2) == 0 {
        q.push('^');
    }
    let mut i = a;
    while i < b {
        let c = chars[i];
        let run = |pred: fn(&char) -> bool| chars[i..b].iter().take_while(|x| pred(x)).count();
        match r.below(6) {
            0 if c.is_ascii_digit() => {
                q.push_str(r"\d+");
                i += run(char::is_ascii_digit);
                continue;
            }
            1 if c.is_ascii_lowercase() => {
                q.push_str("[a-z]+");
                i += run(char::is_ascii_lowercase);
                continue;
            }
            2 if i > a => q.push_str(".*"),
            _ => {}
        }
        if c.is_ascii_alphanumeric() || c == ' ' || !c.is_ascii() {
            q.push(c);
        } else {
            q.push_str(&format!(r"\x{:02x}", c as u32));
        }
        i += 1;
    }
    if b == chars.len() && r.below(2) == 0 {
        q.push('$');
    }
    if r.below(4) == 0 && !q.starts_with('^') && !q.ends_with('$') {
        q = format!(r"({q}|ERROR [a-z]+ \d)");
    }
    q
}

#[test]
fn search_equals_naive_scan() {
    let dir = std::env::temp_dir().join(format!("logjar-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for seed in 1..=6u64 {
        let mut r = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x1234_5678_9abc_def1));
        let path = dir.join(format!("d{seed}.ljar"));
        let opts = Options {
            segment_lines: 50 + r.below(400),
            threads: 1 + r.below(4),
            level: 1 + r.below(5) as i32,
            ..Options::default()
        };
        let mut streams: Vec<(String, String, Vec<Line>)> = Vec::new();
        let mut t = 1_615_500_000_000i64;
        for s in 0..3 {
            let n = 300 + r.below(1500);
            let crlf = r.below(3) == 0;
            let mut lines: Vec<(String, Option<i64>)> =
                (0..n).map(|_| line(&mut r, &mut t)).collect();
            if crlf {
                lines.iter_mut().for_each(|(l, _)| l.push('\r'));
            }
            let mut text = lines
                .iter()
                .map(|(l, _)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            text.push('\n');
            streams.push((format!("s{s}.log"), text, lines));
        }
        // Write in two sessions so appends are exercised.
        let mut w = Writer::create(&path, opts.clone()).unwrap();
        for (name, text, _) in &streams[..2] {
            let half = half_at_newline(text);
            w.add_stream(name, &text.as_bytes()[..half]).unwrap();
        }
        w.finish().unwrap();
        let mut w = Writer::append(&path, opts).unwrap();
        for (name, text, _) in &streams[..2] {
            let half = half_at_newline(text);
            w.add_stream(name, &text.as_bytes()[half..]).unwrap();
        }
        w.add_stream(&streams[2].0, streams[2].1.as_bytes())
            .unwrap();
        w.finish().unwrap();

        let a = Archive::open(&path).unwrap();
        for (id, (_, text, _)) in streams.iter().enumerate() {
            let mut out = Vec::new();
            a.write_stream(id as u32, &mut out).unwrap();
            assert_eq!(out, text.as_bytes(), "seed {seed} stream {id} roundtrip");
        }

        let all: Vec<&str> = streams
            .iter()
            .flat_map(|(_, _, ls)| ls.iter().map(|(l, _)| l.as_str()))
            .collect();
        for _ in 0..80 {
            let regex = r.below(2) == 0;
            let pat = if regex {
                random_regex(&mut r, &all)
            } else {
                random_query(&mut r, &all)
            };
            let q = if regex {
                Query::regex(&pat)
            } else {
                Query::new(&pat)
            };
            let q = q
                .unwrap_or_else(|e| panic!("{pat:?}: {e}"))
                .ignore_case(r.below(4) == 0);
            let window = (r.below(3) == 0).then(|| {
                let lo = 1_615_500_000 + r.below(86_400 * 3) as i64;
                (
                    lo * 1_000_000_000,
                    (lo + r.below(86_400) as i64) * 1_000_000_000,
                )
            });
            let q = match window {
                Some((lo, hi)) => q.after(lo).before(hi),
                None => q,
            };
            for (id, (_, _, lines)) in streams.iter().enumerate() {
                let mut got = Vec::new();
                a.search(&q, &[id as u32], |m| {
                    got.push(m.line_number);
                    true
                })
                .unwrap();
                assert_eq!(
                    got,
                    naive(lines, &q, window),
                    "seed {seed} stream {id} query {pat:?} window {window:?}"
                );
            }
        }
    }
}

/// Byte offset just past the last newline in the first half of `text`.
fn half_at_newline(text: &str) -> usize {
    let b = text.as_bytes();
    b[..b.len() / 2]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |i| i + 1)
}
