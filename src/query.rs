//! Queries and the template-level pruning that makes search fast.
//!
//! A query is one or more patterns (globs or regexes), any of which may
//! match anywhere in a line. Matching is always confirmed on the fully
//! decoded line, so results are exact. The speed comes from proving, per
//! template, that *no* line using it can match, before decoding any.
//!
//! The proof is an automaton intersection. Each pattern compiles to a
//! position automaton (see `crate::regex`). A template is a sequence of
//! literal text and typed variable slots; each slot stands for a language
//! of strings (`[-0-9]+` for integers, the segment's actual dictionary
//! values for dictionary variables, and so on). Running the automaton over
//! that symbolic sequence yields every state some line of the template
//! could reach. If no accepting state is reachable, the template is
//! skipped; if every template in a segment is skipped, the segment's bulky
//! blocks are never inflated.
//!
//! Each step over-approximates the real lines, never under-approximates, so
//! pruning can only skip work that would have found nothing.

use std::collections::HashMap;

use crate::message::{self, Kind, Piece};
use crate::regex::{Prog, Set};
use crate::timestamp::Spec;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    Any,
    Star,
}

#[derive(Clone, Debug)]
enum Source {
    Glob(String),
    Regex(String),
}

#[derive(Clone, Debug)]
struct Pattern {
    /// Always present for regexes; `None` for a glob too long to compile.
    prog: Option<Prog>,
    /// Globs keep their token form: the two-pointer matcher is faster than
    /// stepping the automaton for the final per-line check.
    glob: Option<Vec<Tok>>,
}

/// A compiled search: one or more patterns (any may match), plus optional
/// inversion and time window.
#[derive(Clone, Debug)]
pub struct Query {
    sources: Vec<Source>,
    pats: Vec<Pattern>,
    ignore_case: bool,
    invert: bool,
    pub(crate) after: Option<i64>,
    pub(crate) before: Option<i64>,
}

fn glob_toks(pattern: &str) -> Vec<Tok> {
    let mut toks = vec![Tok::Star];
    let mut it = pattern.bytes();
    while let Some(b) = it.next() {
        let t = match b {
            b'*' => Tok::Star,
            b'?' => Tok::Any,
            b'\\' => Tok::Lit(it.next().unwrap_or(b'\\')),
            b => Tok::Lit(b),
        };
        if !(t == Tok::Star && toks.last() == Some(&Tok::Star)) {
            toks.push(t);
        }
    }
    if toks.last() != Some(&Tok::Star) {
        toks.push(Tok::Star);
    }
    toks
}

fn compile(src: &Source, ignore_case: bool) -> Result<Pattern> {
    Ok(match src {
        // Globs can't be malformed, only too long for an automaton; those
        // still match, they just can't prune.
        Source::Glob(g) => Pattern {
            prog: Prog::glob(g, ignore_case).ok(),
            glob: Some(glob_toks(g)),
        },
        Source::Regex(r) => Pattern {
            prog: Some(Prog::regex(r, ignore_case)?),
            glob: None,
        },
    })
}

impl Query {
    fn from(src: Source) -> Result<Query> {
        let mut q = Query {
            sources: Vec::new(),
            pats: Vec::new(),
            ignore_case: false,
            invert: false,
            after: None,
            before: None,
        };
        q.push(src)?;
        Ok(q)
    }

    fn push(&mut self, src: Source) -> Result<()> {
        self.pats.push(compile(&src, self.ignore_case)?);
        self.sources.push(src);
        Ok(())
    }

    /// Parses a glob: `*` any run, `?` any byte, `\` escapes. The pattern
    /// matches anywhere in a line. An empty pattern matches every line.
    pub fn new(pattern: &str) -> Result<Query> {
        Query::from(Source::Glob(pattern.to_string()))
    }

    /// Parses a regular expression, matched anywhere in a line unless
    /// anchored with `^`/`$`. Byte-oriented; supports classes, `\d \w \s`,
    /// groups, `|`, `* + ?` and `{m,n}`.
    pub fn regex(pattern: &str) -> Result<Query> {
        Query::from(Source::Regex(pattern.to_string()))
    }

    /// Adds a glob alternative: lines matching any pattern match the query.
    pub fn or(mut self, pattern: &str) -> Result<Query> {
        self.push(Source::Glob(pattern.to_string()))?;
        Ok(self)
    }

    /// Adds a regex alternative.
    pub fn or_regex(mut self, pattern: &str) -> Result<Query> {
        self.push(Source::Regex(pattern.to_string()))?;
        Ok(self)
    }

    /// ASCII case-insensitive matching.
    pub fn ignore_case(mut self, yes: bool) -> Query {
        if yes != self.ignore_case {
            self.ignore_case = yes;
            self.pats = self
                .sources
                .iter()
                .map(|s| compile(s, yes).expect("pattern compiled before"))
                .collect();
        }
        self
    }

    /// Select lines that match none of the patterns (the time window still
    /// applies as a filter). Inverted queries cannot prune templates.
    pub fn invert(mut self, yes: bool) -> Query {
        self.invert = yes;
        self
    }

    /// Only lines whose timestamp is at or after `nanos` (Unix epoch, UTC).
    pub fn after(mut self, nanos: i64) -> Query {
        self.after = Some(nanos);
        self
    }

    /// Only lines whose timestamp is strictly before `nanos`.
    pub fn before(mut self, nanos: i64) -> Query {
        self.before = Some(nanos);
        self
    }

    /// Parses `--after`/`--before` style text into nanoseconds.
    pub fn parse_time(s: &str) -> Result<i64> {
        crate::timestamp::parse_bound(s)
            .ok_or_else(|| Error::Query(format!("unrecognized time {s:?}")))
    }

    pub(crate) fn has_time_filter(&self) -> bool {
        self.after.is_some() || self.before.is_some()
    }

    pub(crate) fn time_ok(&self, ns: i64) -> bool {
        self.after.is_none_or(|a| ns >= a) && self.before.is_none_or(|b| ns < b)
    }

    /// Whether the window overlaps `[lo, hi]`.
    pub(crate) fn range_ok(&self, lo: i64, hi: i64) -> bool {
        self.after.is_none_or(|a| hi >= a) && self.before.is_none_or(|b| lo < b)
    }

    /// Exact check on a decoded line (ignores the time window).
    pub fn is_match(&self, line: &[u8]) -> bool {
        self.pats.iter().any(|p| match &p.glob {
            Some(toks) => self.glob(toks, line),
            None => p.prog.as_ref().is_some_and(|r| r.is_match(line)),
        }) != self.invert
    }

    fn eq(&self, p: u8, b: u8) -> bool {
        if self.ignore_case {
            p.eq_ignore_ascii_case(&b)
        } else {
            p == b
        }
    }

    fn glob(&self, p: &[Tok], line: &[u8]) -> bool {
        let (mut pi, mut si) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while si < line.len() {
            match p.get(pi) {
                Some(Tok::Star) => {
                    star = Some((pi, si));
                    pi += 1;
                }
                Some(Tok::Any) => {
                    pi += 1;
                    si += 1;
                }
                Some(&Tok::Lit(c)) if self.eq(c, line[si]) => {
                    pi += 1;
                    si += 1;
                }
                _ => match star {
                    Some((sp, mark)) => {
                        pi = sp + 1;
                        si = mark + 1;
                        star = Some((sp, mark + 1));
                    }
                    None => return false,
                },
            }
        }
        p[pi..].iter().all(|t| *t == Tok::Star)
    }
}

/// One pattern's automaton with the byte classes of a segment's variable
/// slots precomputed.
pub(crate) struct Pruner<'q> {
    prog: &'q Prog,
    int_class: Set,
    float_class: Set,
    dict_class: Set,
    ts_class: Set,
}

impl<'q> Pruner<'q> {
    /// One pruner per pattern, or `None` when pruning can't help: the query
    /// is inverted, or some pattern matches the empty string (and so every
    /// line), or a glob was too long to get an automaton. Callers then just
    /// verify every line.
    pub fn all(q: &'q Query, specs: &[Spec]) -> Option<Vec<Pruner<'q>>> {
        if q.invert {
            return None;
        }
        let progs: Vec<&Prog> = q
            .pats
            .iter()
            .map(|p| p.prog.as_ref())
            .collect::<Option<_>>()?;
        if progs.iter().any(|p| p.nullable) {
            return None;
        }
        let ts_alpha = ts_alphabet(specs);
        Some(
            progs
                .into_iter()
                .map(|prog| Pruner {
                    prog,
                    int_class: prog.mask(|b| b.is_ascii_digit() || b == b'-'),
                    float_class: prog.mask(|b| b.is_ascii_digit() || b == b'-' || b == b'.'),
                    dict_class: prog.mask(|b| !message::is_delim(b)),
                    ts_class: prog.mask(|b| ts_alpha[b as usize]),
                })
                .collect(),
        )
    }

    /// Could any line of this template, under any of the segment's
    /// timestamp formats (or none), match? With `dict`, dictionary slots are
    /// limited to the segment's real values; without it, to their class.
    pub fn template_may_match(&self, pieces: &[Piece], mut dict: Option<&mut DictStates>) -> bool {
        let p = self.prog;
        // Leading timestamp: zero or more bytes of the timestamp alphabet.
        // After it we may or may not still be at the start of the line;
        // keeping `at_start` true over-approximates both cases.
        let mut s = p.plus(0, true, self.ts_class);
        let mut at_start = true;
        if p.accepts_mid(s) {
            return true;
        }
        for (i, piece) in pieces.iter().enumerate() {
            s = match piece {
                // Mirror is_match: an end anchor ignores the line's final CR,
                // which (being a delimiter) is always template text.
                Piece::Text(t) if p.end_anchor && i + 1 == pieces.len() => {
                    match run_hit(p, s, at_start, t.strip_suffix(b"\r").unwrap_or(t)) {
                        Some(s) => s,
                        None => return true,
                    }
                }
                Piece::Text(t) => match run_hit(p, s, at_start, t) {
                    Some(s) => s,
                    None => return true,
                },
                Piece::Var(Kind::Int) => p.plus(s, at_start, self.int_class),
                Piece::Var(Kind::Float) => p.plus(s, at_start, self.float_class),
                Piece::Var(Kind::Dict) => match dict.as_deref_mut() {
                    Some(d) => d.after(self, s, at_start),
                    None => p.plus(s, at_start, self.dict_class),
                },
            };
            at_start = false;
            if p.accepts_mid(s) {
                return true;
            }
        }
        s & p.last != 0
    }
}

/// Memoized "states after reading some dictionary value" for one segment
/// and one pattern.
pub(crate) struct DictStates<'d> {
    dict: &'d [Vec<u8>],
    memo: HashMap<(Set, bool), Set>,
}

impl<'d> DictStates<'d> {
    pub fn new(dict: &'d [Vec<u8>]) -> Self {
        DictStates {
            dict,
            memo: HashMap::new(),
        }
    }

    fn after(&mut self, pr: &Pruner<'_>, s: Set, at_start: bool) -> Set {
        if let Some(&r) = self.memo.get(&(s, at_start)) {
            return r;
        }
        // ponytail: scans the whole dictionary once per distinct state set;
        // an FST or suffix index over the dictionary is the upgrade if
        // dictionaries get huge.
        let full = pr.prog.plus(s, at_start, pr.dict_class);
        let mut r = 0;
        for v in self.dict {
            match run_hit(pr.prog, s, at_start, v) {
                Some(after) => r |= after,
                // A match ends inside this value: report it through `last`.
                None => {
                    r |= pr.prog.last;
                    break;
                }
            }
            if r == full {
                break; // can't get any wider than the class bound
            }
        }
        self.memo.insert((s, at_start), r);
        r
    }
}

/// Steps over literal bytes; `None` if a match can end partway through.
fn run_hit(p: &Prog, mut s: Set, mut at_start: bool, bytes: &[u8]) -> Option<Set> {
    for &b in bytes {
        s = p.step(s, at_start, b);
        at_start = false;
        if p.accepts_mid(s) {
            return None;
        }
    }
    Some(s)
}

fn ts_alphabet(specs: &[Spec]) -> [bool; 256] {
    let mut a = [false; 256];
    for spec in specs {
        let mut it = spec.text.bytes();
        while let Some(b) = it.next() {
            if b != b'%' {
                a[b as usize] = true;
                continue;
            }
            match it.next() {
                Some(b'b') => b"JanFebMrApyulgSOctNovDec"
                    .iter()
                    .for_each(|&c| a[c as usize] = true),
                Some(b'a') => b"SunMoTueWdhFriSat"
                    .iter()
                    .for_each(|&c| a[c as usize] = true),
                Some(b'e') => {
                    a[b' ' as usize] = true;
                    (b'0'..=b'9').for_each(|c| a[c as usize] = true);
                }
                _ => (b'0'..=b'9').for_each(|c| a[c as usize] = true),
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpl(msg: &str) -> Vec<Piece> {
        let (mut t, mut v) = (Vec::new(), Vec::new());
        message::encode(msg.as_bytes(), &mut t, &mut v);
        message::pieces(&t).unwrap()
    }

    #[test]
    fn glob_semantics() {
        let q = |p: &str| Query::new(p).unwrap();
        assert!(q("ERROR").is_match(b"12:00 ERROR disk full"));
        assert!(q("ERR*full").is_match(b"12:00 ERROR disk full"));
        assert!(q("d?sk").is_match(b"disk"));
        assert!(!q("d?sk").is_match(b"dsk"));
        assert!(q("").is_match(b""));
        assert!(q(r"a\*b").is_match(b"xa*by"));
        assert!(!q(r"a\*b").is_match(b"axxb"));
        assert!(!q("error").is_match(b"ERROR"));
        assert!(q("error").ignore_case(true).is_match(b"ERROR"));
        assert!(q("a*a*a*b").is_match(b"aaaaaaaaab"));
        assert!(!q("a*a*a*b").is_match(b"aaaaaaaaaa"));
    }

    #[test]
    fn long_globs_match_without_pruning() {
        let long = "x".repeat(300);
        let q = Query::new(&long).unwrap();
        assert!(q.is_match(format!("a{long}b").as_bytes()));
        assert!(!q.is_match(&long.as_bytes()[1..]));
        assert!(Pruner::all(&q, &[]).is_none());
        assert!(Query::regex(&long).is_err());
    }

    fn check(q: &Query, specs: &[Spec], msg: &str) -> bool {
        Pruner::all(q, specs)
            .unwrap()
            .remove(0)
            .template_may_match(&tpl(msg), None)
    }

    #[test]
    fn template_pruning() {
        let specs = [Spec::new("%Y-%m-%d %H:%M:%S,%3")];
        let g = |pat: &str, msg: &str| check(&Query::new(pat).unwrap(), &specs, msg);
        // Static text decides.
        assert!(g("Exception", "java.lang.NullPointerException at foo"));
        // Integer slots cannot hold letters; dictionary slots could, until the
        // real dictionary is consulted (see dictionary_refinement).
        assert!(!g("Exception", "Received 12 bytes in 0.5 s"));
        assert!(g("Exception", "Received block blk_1 of size 5"));
        // Values can only come from slots of a compatible type.
        assert!(g("size 671", "Received block blk_1 of size 67108864"));
        assert!(!g("size abc", "Received block blk_1 of size 67108864"));
        assert!(g("blk_-16*size", "Received block blk_1 of size 67108864"));
        // Queries touching the timestamp still match via the ts alphabet.
        assert!(g("2015-10-18 18:01", "INFO main started"));
        assert!(!g("2015-10-18 ERROR", "INFO main started"));
    }

    #[test]
    fn regex_pruning_and_anchors() {
        let specs = [Spec::new("%Y-%m-%d %H:%M:%S,%3")];
        let r = |pat: &str, msg: &str| check(&Query::regex(pat).unwrap(), &specs, msg);
        assert!(r(r"size \d{5,}", "Received block blk_1 of size 67108864"));
        assert!(!r(
            r"of size [a-z]",
            "Received block blk_1 of size 67108864"
        ));
        assert!(r(
            "(WARN|ERROR) .*timeout",
            "ERROR request timeout after 3 s"
        ));
        assert!(!r(
            "(WARN|ERROR) .*timeout",
            "INFO request timeout after 3 s"
        ));
        // End anchor: the template must be able to end in a match.
        assert!(r(r"ms$", "GC pause 4.5 ms"));
        assert!(!r(r"ms$", "GC pause 4.5 ms total"));
        assert!(r(r"\d$", "retries 3"));
        assert!(r(r"\d$", "retries 3\r"));
        assert!(!r(r"\d$", "retries 3 \r"));
        // Start anchor: only reachable through the (optional) timestamp.
        assert!(r("^2015-10", "INFO started"));
        assert!(!r("^INFO x", "WARN INFO x"));
        assert!(r("^INFO x", "INFO x"));
    }

    #[test]
    fn dictionary_refinement() {
        let specs: [Spec; 0] = [];
        let q = Query::new("blk_42 ").unwrap();
        let pr = Pruner::all(&q, &specs).unwrap().remove(0);
        let t = tpl("Deleting block blk_1 file /data/x");
        let has = vec![b"blk_1".to_vec(), b"blk_42".to_vec()];
        let hasnt = vec![b"blk_1".to_vec(), b"blk_420".to_vec()];
        assert!(pr.template_may_match(&t, None));
        assert!(pr.template_may_match(&t, Some(&mut DictStates::new(&has))));
        assert!(!pr.template_may_match(&t, Some(&mut DictStates::new(&hasnt))));
    }

    /// Pruning must never reject a template that a real line matches.
    #[test]
    fn pruning_is_sound_on_random_lines() {
        let words = [
            "ERROR", "blk_", "-", "12", "0.5", "a1b", " ", ":", "/", "x", "=", "007", ".", "Z",
        ];
        let mut s = 0x2545f4914f6cdd1du64;
        let mut rnd = |n: usize| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s % n as u64) as usize
        };
        let specs = [Spec::new("%Y-%m-%d %H:%M:%S")];
        for _ in 0..4000 {
            let mut line = String::new();
            if rnd(2) == 0 {
                line.push_str("2016-02-29 23:59:01");
            }
            for _ in 0..rnd(8) {
                line.push_str(words[rnd(words.len())]);
            }
            let start = rnd(line.len() + 1);
            let end = start + rnd(line.len() - start + 1);
            let piece = &line[start..end];
            let q = match rnd(3) {
                // Glob with a wildcard swapped in.
                0 => {
                    let mut pat = piece
                        .replace('\\', "\\\\")
                        .replace('*', "\\*")
                        .replace('?', "\\?");
                    if pat.len() > 2 {
                        let k = rnd(pat.len());
                        if pat.is_char_boundary(k)
                            && pat.is_char_boundary(k + 1)
                            && &pat[k..k + 1] != "\\"
                        {
                            pat.replace_range(k..k + 1, if rnd(2) == 0 { "*" } else { "?" });
                        }
                    }
                    Query::new(&pat).unwrap()
                }
                // Regex: escaped literal, digits generalized, maybe anchored.
                _ => {
                    let mut re = String::new();
                    for c in piece.chars() {
                        match c {
                            '0'..='9' if rnd(2) == 0 => re.push_str("\\d+"),
                            c if c.is_ascii_alphanumeric() || c == ' ' => re.push(c),
                            c => re.push_str(&format!("\\x{:02x}", c as u32)),
                        }
                    }
                    if start == 0 && rnd(2) == 0 {
                        re.insert(0, '^');
                    }
                    if end == line.len() && rnd(2) == 0 {
                        re.push('$');
                    }
                    Query::regex(&re).unwrap()
                }
            };
            if !q.is_match(line.as_bytes()) {
                // `\d+` can't match the "-" of a negative-looking glob swap etc.;
                // only matching lines are interesting for soundness.
                continue;
            }
            let msg = match crate::timestamp::detect_with(&specs, 0, line.as_bytes()) {
                Some((_, _, n)) => &line[n..],
                None => &line[..],
            };
            let (mut t, mut vars) = (Vec::new(), Vec::new());
            message::encode(msg.as_bytes(), &mut t, &mut vars);
            let dict: Vec<Vec<u8>> = vars
                .iter()
                .filter_map(|v| match v {
                    message::Var::Dict(d) => Some(d.to_vec()),
                    _ => None,
                })
                .collect();
            // Patterns matching the empty string match everything: nothing to prune.
            let Some(mut prs) = Pruner::all(&q, &specs) else {
                continue;
            };
            let pr = prs.remove(0);
            let pieces = message::pieces(&t).unwrap();
            assert!(
                pr.template_may_match(&pieces, None),
                "coarse: {q:?} in {line:?}"
            );
            assert!(
                pr.template_may_match(&pieces, Some(&mut DictStates::new(&dict))),
                "dict: {q:?} in {line:?}"
            );
        }
    }
}
