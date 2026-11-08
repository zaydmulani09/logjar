//! Glob queries and the template-level pruning that makes search fast.
//!
//! A query is a glob (`*` any run, `?` any byte, `\` escapes) matched
//! against any substring of a line. Matching is always confirmed on the
//! fully decoded line, so results are exact. The speed comes from proving,
//! per template, that *no* line using it can match, before decoding any.
//!
//! The proof is an automaton intersection. The glob compiles to a
//! bit-parallel NFA (one bit per pattern position). A template is a
//! sequence of literal text and typed variable slots; each slot stands for
//! a language of strings (`-?[0-9]+` for integers, the segment's actual
//! dictionary values for dictionary variables, and so on). Running the NFA
//! over that symbolic sequence yields the set of pattern positions any line
//! of the template could reach. If the accept position is unreachable, the
//! template is skipped; if every template in a segment is skipped, the
//! segment's bulky blocks are never inflated.
//!
//! Each step over-approximates the real lines, never under-approximates, so
//! pruning can only skip work that would have found nothing.

use std::collections::HashMap;

use crate::message::{self, Kind, Piece};
use crate::timestamp::Spec;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    Any,
    Star,
}

/// A compiled search: glob pattern plus optional time window.
#[derive(Clone, Debug)]
pub struct Query {
    toks: Vec<Tok>,
    ignore_case: bool,
    pub(crate) after: Option<i64>,
    pub(crate) before: Option<i64>,
}

impl Query {
    /// Parses a glob. The pattern matches anywhere in a line, as if wrapped
    /// in `*...*`. An empty pattern matches every line.
    pub fn new(pattern: &str) -> Result<Query> {
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
        Ok(Query { toks, ignore_case: false, after: None, before: None })
    }

    /// ASCII case-insensitive matching.
    pub fn ignore_case(mut self, yes: bool) -> Query {
        self.ignore_case = yes;
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
        crate::timestamp::parse_bound(s).ok_or_else(|| Error::Query(format!("unrecognized time {s:?}")))
    }

    pub(crate) fn has_time_filter(&self) -> bool {
        self.after.is_some() || self.before.is_some()
    }

    pub(crate) fn time_ok(&self, ns: i64) -> bool {
        self.after.map_or(true, |a| ns >= a) && self.before.map_or(true, |b| ns < b)
    }

    /// Whether the window overlaps `[lo, hi]`.
    pub(crate) fn range_ok(&self, lo: i64, hi: i64) -> bool {
        self.after.map_or(true, |a| hi >= a) && self.before.map_or(true, |b| lo < b)
    }

    /// True if the pattern is just `*`: every line matches, pruning is moot.
    pub(crate) fn matches_everything(&self) -> bool {
        self.toks == [Tok::Star]
    }

    fn eq(&self, p: u8, b: u8) -> bool {
        if self.ignore_case {
            p.eq_ignore_ascii_case(&b)
        } else {
            p == b
        }
    }

    /// Exact check on a decoded line.
    pub fn is_match(&self, line: &[u8]) -> bool {
        let p = &self.toks;
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

/// Pattern positions as a bitset: bit `j` = "next token to match is `j`",
/// bit `m` = accepted.
type Set = u128;

/// The glob as a bit-parallel NFA, specialised for one segment.
pub(crate) struct Nfa<'q> {
    q: &'q Query,
    star: Set,
    accept: Set,
    /// Positions that consume byte `b` and advance (literal `b` or `?`).
    lit: Box<[Set; 256]>,
    /// Same, for every byte of a variable's character class.
    int_class: Set,
    float_class: Set,
    dict_class: Set,
    ts_class: Set,
}

impl<'q> Nfa<'q> {
    /// `None` if the pattern is too long for the bitset; callers then skip
    /// pruning and just verify every line.
    pub fn new(q: &'q Query, specs: &[Spec]) -> Option<Nfa<'q>> {
        let m = q.toks.len();
        if m >= Set::BITS as usize {
            return None;
        }
        let mut lit = Box::new([0 as Set; 256]);
        let mut star = 0;
        for (j, t) in q.toks.iter().enumerate() {
            match *t {
                Tok::Star => star |= 1 << j,
                Tok::Any => lit.iter_mut().for_each(|s| *s |= 1 << j),
                Tok::Lit(c) => {
                    for b in 0..=255u8 {
                        if q.eq(c, b) {
                            lit[b as usize] |= 1 << j;
                        }
                    }
                }
            }
        }
        let class = |pred: &dyn Fn(u8) -> bool| (0..=255u8).filter(|&b| pred(b)).fold(0, |s, b| s | lit[b as usize]);
        let int_class = class(&|b| b.is_ascii_digit() || b == b'-');
        let float_class = class(&|b| b.is_ascii_digit() || b == b'-' || b == b'.');
        let dict_class = class(&|b| !message::is_delim(b));
        let ts_alpha = ts_alphabet(specs);
        let ts_class = class(&|b| ts_alpha[b as usize]);
        Some(Nfa { q, star, accept: 1 << m, lit, int_class, float_class, dict_class, ts_class })
    }

    fn close(&self, s: Set) -> Set {
        s | ((s & self.star) << 1)
    }

    pub fn start(&self) -> Set {
        self.close(1)
    }

    fn step(&self, s: Set, b: u8) -> Set {
        self.close(((s & self.lit[b as usize]) << 1) | (s & self.star))
    }

    fn step_class(&self, s: Set, class: Set) -> Set {
        self.close(((s & class) << 1) | (s & self.star))
    }

    /// States after one or more bytes of `class`.
    fn plus(&self, s: Set, class: Set) -> Set {
        let mut reach = self.step_class(s, class);
        let mut frontier = reach;
        loop {
            frontier = self.step_class(frontier, class);
            if frontier & !reach == 0 {
                return reach;
            }
            reach |= frontier;
        }
    }

    fn run(&self, mut s: Set, bytes: &[u8]) -> Set {
        for &b in bytes {
            s = self.step(s, b);
        }
        s
    }

    pub fn accepts(&self, s: Set) -> bool {
        s & self.accept != 0
    }

    /// Could any line of this template, under any of the segment's
    /// timestamp formats (or none), match? With `dict`, dictionary slots are
    /// limited to the segment's real values; without it, to their class.
    pub fn template_may_match(&self, pieces: &[Piece], dict: Option<&mut DictStates>) -> bool {
        let mut dict = dict;
        // Leading timestamp: zero or more bytes of the timestamp alphabet.
        let mut s = self.start();
        s |= self.plus(s, self.ts_class);
        if self.accepts(s) {
            return true;
        }
        for p in pieces {
            s = match p {
                Piece::Text(t) => self.run(s, t),
                Piece::Var(Kind::Int) => self.plus(s, self.int_class),
                Piece::Var(Kind::Float) => self.plus(s, self.float_class),
                Piece::Var(Kind::Dict) => match dict.as_deref_mut() {
                    Some(d) => d.after(self, s),
                    None => self.plus(s, self.dict_class),
                },
            };
            if self.accepts(s) {
                return true;
            }
        }
        false
    }

    pub fn query(&self) -> &Query {
        self.q
    }
}

/// Memoized "states after reading some dictionary value" for one segment.
pub(crate) struct DictStates<'d> {
    dict: &'d [Vec<u8>],
    memo: HashMap<Set, Set>,
}

impl<'d> DictStates<'d> {
    pub fn new(dict: &'d [Vec<u8>]) -> Self {
        DictStates { dict, memo: HashMap::new() }
    }

    fn after(&mut self, nfa: &Nfa<'_>, s: Set) -> Set {
        if let Some(&r) = self.memo.get(&s) {
            return r;
        }
        // ponytail: scans the whole dictionary once per distinct state set;
        // an FST or suffix index over the dictionary is the upgrade if
        // dictionaries get huge.
        let mut r = 0;
        let full = nfa.plus(s, nfa.dict_class);
        for v in self.dict {
            r |= nfa.run(s, v);
            if r == full {
                break; // can't get any wider than the class bound
            }
        }
        self.memo.insert(s, r);
        r
    }
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
                Some(b'b') => b"JanFebMrApyulgSOctNovDec".iter().for_each(|&c| a[c as usize] = true),
                Some(b'a') => b"SunMoTueWdhFriSat".iter().for_each(|&c| a[c as usize] = true),
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
    fn template_pruning() {
        let specs = [Spec::new("%Y-%m-%d %H:%M:%S,%3")];
        let check = |pat: &str, msg: &str| {
            let q = Query::new(pat).unwrap();
            Nfa::new(&q, &specs).unwrap().template_may_match(&tpl(msg), None)
        };
        // Static text decides.
        assert!(check("Exception", "java.lang.NullPointerException at foo"));
        // Integer slots cannot hold letters; dictionary slots could, until the
        // real dictionary is consulted (see dictionary_refinement).
        assert!(!check("Exception", "Received 12 bytes in 0.5 s"));
        assert!(check("Exception", "Received block blk_1 of size 5"));
        // Values can only come from slots of a compatible type.
        assert!(check("size 671", "Received block blk_1 of size 67108864"));
        assert!(!check("size abc", "Received block blk_1 of size 67108864"));
        assert!(check("blk_-16*size", "Received block blk_1 of size 67108864"));
        // Queries touching the timestamp still match via the ts alphabet.
        assert!(check("2015-10-18 18:01", "INFO main started"));
        assert!(!check("2015-10-18 ERROR", "INFO main started"));
    }

    #[test]
    fn dictionary_refinement() {
        let specs: [Spec; 0] = [];
        let q = Query::new("blk_42 ").unwrap();
        let nfa = Nfa::new(&q, &specs).unwrap();
        let t = tpl("Deleting block blk_1 file /data/x");
        let has = vec![b"blk_1".to_vec(), b"blk_42".to_vec()];
        let hasnt = vec![b"blk_1".to_vec(), b"blk_420".to_vec()];
        assert!(nfa.template_may_match(&t, None));
        assert!(nfa.template_may_match(&t, Some(&mut DictStates::new(&has))));
        assert!(!nfa.template_may_match(&t, Some(&mut DictStates::new(&hasnt))));
    }

    /// Pruning must never reject a template that a real line matches.
    #[test]
    fn pruning_is_sound_on_random_lines() {
        let words = ["ERROR", "blk_", "-", "12", "0.5", "a1b", " ", ":", "/", "x", "=", "007", ".", "Z"];
        let mut s = 0x2545f4914f6cdd1du64;
        let mut rnd = |n: usize| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s % n as u64) as usize
        };
        let specs = [Spec::new("%Y-%m-%d %H:%M:%S")];
        for _ in 0..3000 {
            let mut line = String::new();
            if rnd(2) == 0 {
                line.push_str("2016-02-29 23:59:01");
            }
            for _ in 0..rnd(8) {
                line.push_str(words[rnd(words.len())]);
            }
            let start = rnd(line.len() + 1);
            let end = start + rnd(line.len() - start + 1);
            let mut pat: String = line[start..end].to_string();
            if pat.len() > 2 && rnd(3) == 0 {
                let k = rnd(pat.len());
                pat.replace_range(k..k + 1, if rnd(2) == 0 { "*" } else { "?" });
            }
            let q = Query::new(&pat).unwrap();
            assert!(q.is_match(line.as_bytes()), "{pat:?} in {line:?}");
            let (ts_len, msg) = match crate::timestamp::detect_with(&specs, 0, line.as_bytes()) {
                Some((_, _, n)) => (n, &line[n..]),
                None => (0, &line[..]),
            };
            let _ = ts_len;
            let (mut t, mut vars) = (Vec::new(), Vec::new());
            message::encode(msg.as_bytes(), &mut t, &mut vars);
            let dict: Vec<Vec<u8>> = vars
                .iter()
                .filter_map(|v| match v {
                    message::Var::Dict(d) => Some(d.to_vec()),
                    _ => None,
                })
                .collect();
            let nfa = Nfa::new(&q, &specs).unwrap();
            let pieces = message::pieces(&t).unwrap();
            assert!(nfa.template_may_match(&pieces, None), "coarse: {pat:?} in {line:?}");
            assert!(
                nfa.template_may_match(&pieces, Some(&mut DictStates::new(&dict))),
                "dict: {pat:?} in {line:?}"
            );
        }
    }
}
