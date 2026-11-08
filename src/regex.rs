//! A small byte-oriented regex engine built for template pruning.
//!
//! Patterns compile to a Glushkov position automaton: one state per literal
//! or class in the pattern, no epsilon moves, transitions stored as one
//! bitset of follow positions per state. Sets of states are `u128`s, so a
//! pattern may have at most 127 positions. Globs compile to the same
//! automaton (`*` is `.*`, `?` is `.`), so one engine does all pruning.
//!
//! The automaton can be stepped over concrete bytes (to match a line) or
//! over byte *classes* (to reason about every possible value of a variable
//! slot at once); see `crate::query`.
//!
//! Supported syntax: literals, `.`, `[...]` and `[^...]` with ranges,
//! `\d \D \w \W \s \S \t \n \r \xHH`, escaped metacharacters, `(...)`,
//! `|`, `* + ?`, `{m}`, `{m,}`, `{m,n}`, and `^` / `$` at the very start /
//! end of the pattern. Matching is byte-wise and unanchored unless anchored.

use crate::{Error, Result};

pub type Set = u128;

const MAX_POSITIONS: usize = Set::BITS as usize - 1;
const MAX_REPEAT: u32 = 64;

#[derive(Clone, Debug)]
enum Ast {
    Class(Box<[bool; 256]>),
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    Star(Box<Ast>),
    Opt(Box<Ast>),
}

fn class_of(pred: impl Fn(u8) -> bool) -> Box<[bool; 256]> {
    let mut c = Box::new([false; 256]);
    for b in 0..=255u8 {
        c[b as usize] = pred(b);
    }
    c
}

fn byte(b: u8) -> Ast {
    Ast::Class(class_of(|x| x == b))
}

fn any() -> Ast {
    Ast::Class(class_of(|_| true))
}

/// A compiled pattern.
#[derive(Clone, Debug)]
pub struct Prog {
    pub first: Set,
    pub last: Set,
    pub nullable: bool,
    follow: Vec<Set>,
    /// Positions whose class contains byte `b`.
    bytes: Box<[Set; 256]>,
    pub start_anchor: bool,
    pub end_anchor: bool,
}

impl Prog {
    /// Compiles a regular expression.
    pub fn regex(pattern: &str, ignore_case: bool) -> Result<Prog> {
        let mut p = Parser {
            s: pattern.as_bytes(),
            i: 0,
        };
        let start_anchor = p.eat(b'^');
        let ast = p.alt()?;
        let end_anchor = p.eat(b'$');
        if p.i != p.s.len() {
            return Err(match p.s[p.i] {
                b')' => Error::Query("unmatched ')'".into()),
                b'^' | b'$' => Error::Query(
                    "'^' and '$' are only supported at the start and end of the pattern".into(),
                ),
                c => Error::Query(format!("unexpected {:?}", c as char)),
            });
        }
        compile(&ast, ignore_case, start_anchor, end_anchor)
    }

    /// Compiles a glob: `*` any run, `?` any byte, `\` escapes.
    pub fn glob(pattern: &str, ignore_case: bool) -> Result<Prog> {
        let mut parts = Vec::new();
        let mut it = pattern.bytes();
        while let Some(b) = it.next() {
            parts.push(match b {
                b'*' => Ast::Star(Box::new(any())),
                b'?' => any(),
                b'\\' => byte(it.next().unwrap_or(b'\\')),
                b => byte(b),
            });
        }
        // Leading and trailing stars are implied by substring matching.
        while matches!(parts.first(), Some(Ast::Star(_))) {
            parts.remove(0);
        }
        while matches!(parts.last(), Some(Ast::Star(_))) {
            parts.pop();
        }
        compile(&Ast::Concat(parts), ignore_case, false, false)
    }

    #[inline]
    fn follow_of(&self, mut s: Set) -> Set {
        let mut out = 0;
        while s != 0 {
            out |= self.follow[s.trailing_zeros() as usize];
            s &= s - 1;
        }
        out
    }

    /// States that may consume the next byte, given the states `s` that
    /// just consumed one. A new match may start anywhere unless anchored.
    #[inline]
    pub fn next(&self, s: Set, at_start: bool) -> Set {
        let inject = if !self.start_anchor || at_start {
            self.first
        } else {
            0
        };
        self.follow_of(s) | inject
    }

    /// Positions accepting any byte for which `pred` holds.
    pub fn mask(&self, pred: impl Fn(u8) -> bool) -> Set {
        (0..=255u8)
            .filter(|&b| pred(b))
            .fold(0, |m, b| m | self.bytes[b as usize])
    }

    #[inline]
    pub fn step(&self, s: Set, at_start: bool, b: u8) -> Set {
        self.next(s, at_start) & self.bytes[b as usize]
    }

    /// States after one or more bytes drawn from `mask`'s class.
    pub fn plus(&self, s: Set, at_start: bool, mask: Set) -> Set {
        let mut reach = self.next(s, at_start) & mask;
        let mut frontier = reach;
        loop {
            frontier = self.next(frontier, false) & mask;
            if frontier & !reach == 0 {
                return reach;
            }
            reach |= frontier;
        }
    }

    pub fn run(&self, mut s: Set, mut at_start: bool, bytes: &[u8]) -> Set {
        for &b in bytes {
            s = self.step(s, at_start, b);
            at_start = false;
        }
        s
    }

    /// Whether a match can end here, mid-line.
    #[inline]
    pub fn accepts_mid(&self, s: Set) -> bool {
        !self.end_anchor && s & self.last != 0
    }

    pub fn is_match(&self, line: &[u8]) -> bool {
        if self.nullable && (!self.end_anchor || !self.start_anchor || line.is_empty()) {
            return true;
        }
        let mut s = 0;
        for (i, &b) in line.iter().enumerate() {
            s = self.step(s, i == 0, b);
            if self.accepts_mid(s) {
                return true;
            }
        }
        s & self.last != 0
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        // `$` only counts as an anchor at the very end.
        if self.peek() == Some(b) && (b != b'$' || self.i + 1 == self.s.len()) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn alt(&mut self) -> Result<Ast> {
        let mut branches = vec![self.concat()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            branches.push(self.concat()?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap()
        } else {
            Ast::Alt(branches)
        })
    }

    fn concat(&mut self) -> Result<Ast> {
        let mut parts = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' || (c == b'$' && self.i + 1 == self.s.len()) {
                break;
            }
            let atom = self.atom()?;
            parts.push(self.repeat(atom)?);
        }
        Ok(Ast::Concat(parts))
    }

    fn repeat(&mut self, mut atom: Ast) -> Result<Ast> {
        loop {
            let quant = self.peek();
            if matches!(quant, Some(b'*' | b'+' | b'?' | b'{')) {
                self.i += 1;
            }
            let (min, max) = match quant {
                Some(b'*') => (0, None),
                Some(b'+') => (1, None),
                Some(b'?') => (0, Some(1)),
                Some(b'{') => self.bounds()?,
                _ => return Ok(atom),
            };
            let mut parts: Vec<Ast> = (0..min).map(|_| atom.clone()).collect();
            match max {
                None => parts.push(Ast::Star(Box::new(atom.clone()))),
                Some(max) => parts.extend((min..max).map(|_| Ast::Opt(Box::new(atom.clone())))),
            }
            atom = Ast::Concat(parts);
        }
    }

    /// Parses `m}`, `m,}` or `m,n}` after a `{`.
    fn bounds(&mut self) -> Result<(u32, Option<u32>)> {
        let num = |p: &mut Self| -> Option<u32> {
            let start = p.i;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.i += 1;
            }
            std::str::from_utf8(&p.s[start..p.i]).ok()?.parse().ok()
        };
        let bad = || Error::Query("bad {m,n} repetition".into());
        let min = num(self).ok_or_else(bad)?;
        let max = if self.peek() == Some(b',') {
            self.i += 1;
            if self.peek() == Some(b'}') {
                None
            } else {
                Some(num(self).ok_or_else(bad)?)
            }
        } else {
            Some(min)
        };
        if self.peek() != Some(b'}')
            || max.is_some_and(|m| m < min)
            || min.max(max.unwrap_or(0)) > MAX_REPEAT
        {
            return Err(bad());
        }
        self.i += 1;
        Ok((min, max))
    }

    fn atom(&mut self) -> Result<Ast> {
        let c = self
            .peek()
            .ok_or_else(|| Error::Query("unexpected end of pattern".into()))?;
        self.i += 1;
        Ok(match c {
            b'(' => {
                let inner = self.alt()?;
                if self.peek() != Some(b')') {
                    return Err(Error::Query("unclosed '('".into()));
                }
                self.i += 1;
                inner
            }
            b'[' => Ast::Class(self.class()?),
            b'.' => any(),
            b'\\' => Ast::Class(self.escape()?),
            b'*' | b'+' | b'?' | b'{' => {
                return Err(Error::Query(format!(
                    "nothing to repeat before {:?}",
                    c as char
                )))
            }
            b'^' | b'$' => {
                return Err(Error::Query(
                    "'^' and '$' are only supported at the start and end of the pattern".into(),
                ))
            }
            c => byte(c),
        })
    }

    fn escape(&mut self) -> Result<Box<[bool; 256]>> {
        let c = self
            .peek()
            .ok_or_else(|| Error::Query("trailing backslash".into()))?;
        self.i += 1;
        let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let space = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c);
        Ok(match c {
            b'd' => class_of(|b| b.is_ascii_digit()),
            b'D' => class_of(|b| !b.is_ascii_digit()),
            b'w' => class_of(word),
            b'W' => class_of(|b| !word(b)),
            b's' => class_of(space),
            b'S' => class_of(|b| !space(b)),
            b't' => class_of(|b| b == b'\t'),
            b'n' => class_of(|b| b == b'\n'),
            b'r' => class_of(|b| b == b'\r'),
            b'x' => {
                let hex = self
                    .s
                    .get(self.i..self.i + 2)
                    .and_then(|h| std::str::from_utf8(h).ok());
                let v = hex
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| Error::Query("\\x needs two hex digits".into()))?;
                self.i += 2;
                class_of(|b| b == v)
            }
            c => class_of(|b| b == c),
        })
    }

    fn class(&mut self) -> Result<Box<[bool; 256]>> {
        let negate = self.peek() == Some(b'^');
        if negate {
            self.i += 1;
        }
        let mut set = Box::new([false; 256]);
        let mut first = true;
        loop {
            let c = self
                .peek()
                .ok_or_else(|| Error::Query("unclosed '['".into()))?;
            self.i += 1;
            if c == b']' && !first {
                break;
            }
            first = false;
            let lo = if c == b'\\' {
                let e = self.escape()?;
                let single = e.iter().filter(|&&x| x).count() == 1;
                if !single || self.peek() != Some(b'-') {
                    (0..256).for_each(|b| set[b] |= e[b]);
                    continue;
                }
                e.iter().position(|&x| x).unwrap() as u8
            } else {
                c
            };
            if self.peek() == Some(b'-') && self.s.get(self.i + 1).is_some_and(|&n| n != b']') {
                self.i += 1;
                let mut hi = self.peek().unwrap();
                self.i += 1;
                if hi == b'\\' {
                    let e = self.escape()?;
                    hi = e.iter().position(|&x| x).unwrap_or(0) as u8;
                }
                if hi < lo {
                    return Err(Error::Query("reversed range in [...]".into()));
                }
                (lo..=hi).for_each(|b| set[b as usize] = true);
            } else {
                set[lo as usize] = true;
            }
        }
        if negate {
            set.iter_mut().for_each(|x| *x = !*x);
        }
        Ok(set)
    }
}

struct Builder {
    follow: Vec<Set>,
    classes: Vec<Box<[bool; 256]>>,
}

/// Glushkov construction: returns (nullable, first, last) of `ast` and
/// fills in follow sets.
fn glushkov(ast: &Ast, b: &mut Builder) -> Result<(bool, Set, Set)> {
    Ok(match ast {
        Ast::Class(c) => {
            let p = b.classes.len();
            if p >= MAX_POSITIONS {
                return Err(Error::Query(format!(
                    "pattern too large (more than {MAX_POSITIONS} positions)"
                )));
            }
            b.classes.push(c.clone());
            b.follow.push(0);
            (false, 1 << p, 1 << p)
        }
        Ast::Concat(parts) => {
            let (mut nullable, mut first, mut last) = (true, 0, 0);
            for part in parts {
                let (n, f, l) = glushkov(part, b)?;
                for p in bits(last) {
                    b.follow[p] |= f;
                }
                if nullable {
                    first |= f;
                }
                last = if n { last | l } else { l };
                nullable &= n;
            }
            (nullable, first, last)
        }
        Ast::Alt(branches) => {
            let (mut nullable, mut first, mut last) = (false, 0, 0);
            for br in branches {
                let (n, f, l) = glushkov(br, b)?;
                nullable |= n;
                first |= f;
                last |= l;
            }
            (nullable, first, last)
        }
        Ast::Star(inner) => {
            let (_, f, l) = glushkov(inner, b)?;
            for p in bits(l) {
                b.follow[p] |= f;
            }
            (true, f, l)
        }
        Ast::Opt(inner) => {
            let (_, f, l) = glushkov(inner, b)?;
            (true, f, l)
        }
    })
}

fn bits(mut s: Set) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if s == 0 {
            return None;
        }
        let p = s.trailing_zeros() as usize;
        s &= s - 1;
        Some(p)
    })
}

fn compile(ast: &Ast, ignore_case: bool, start_anchor: bool, end_anchor: bool) -> Result<Prog> {
    let mut b = Builder {
        follow: Vec::new(),
        classes: Vec::new(),
    };
    let (nullable, first, last) = glushkov(ast, &mut b)?;
    let mut bytes = Box::new([0 as Set; 256]);
    for (p, class) in b.classes.iter().enumerate() {
        for x in 0..=255u8 {
            let hit = class[x as usize]
                || (ignore_case
                    && (class[x.to_ascii_lowercase() as usize]
                        || class[x.to_ascii_uppercase() as usize]));
            if hit {
                bytes[x as usize] |= 1 << p;
            }
        }
    }
    Ok(Prog {
        first,
        last,
        nullable,
        follow: b.follow,
        bytes,
        start_anchor,
        end_anchor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(re: &str, s: &str) -> bool {
        Prog::regex(re, false).unwrap().is_match(s.as_bytes())
    }

    #[test]
    fn regex_semantics() {
        assert!(m("ERROR", "x ERROR y"));
        assert!(m("ERR(OR|ROR)", "ERRROR"));
        assert!(m("^Jun", "Jun 14"));
        assert!(!m("^Jun", " Jun 14"));
        assert!(m("ms$", "took 5 ms"));
        assert!(!m("ms$", "ms took"));
        assert!(m("^$", ""));
        assert!(!m("^$", "x"));
        assert!(m("a*$", "bbb"));
        assert!(m("[0-9]{3}-[0-9]{4}", "call 555-1234 now"));
        assert!(!m("[0-9]{3}-[0-9]{4}", "call 55-1234 now"));
        assert!(m(r"\d+\.\d+ ms", "pause 412.7 ms"));
        assert!(m("[^a-z]x", "Ax"));
        assert!(!m("^[^a-z]x", "ax"));
        assert!(m(r"\[main\]", "INFO [main] x"));
        assert!(m("colou?r", "color"));
        assert!(m("(ab)+c", "xxababc"));
        assert!(!m("^(ab)+c$", "abac"));
        assert!(m("a{2,}", "baab"));
        assert!(!m("a{2,}", "bab"));
        assert!(m(r"[\d.]+", "1.2"));
        assert!(m("[]x]", "]"));
        assert!(m("[a-]", "-"));
        assert!(Prog::regex("err", true).unwrap().is_match(b"ERROR"));
    }

    #[test]
    fn regex_errors() {
        for bad in [
            "(", "a)", "[abc", "*a", "a{3,1}", "a{99}", r"\x4", "a^b", "a$b", "[z-a]",
        ] {
            assert!(Prog::regex(bad, false).is_err(), "{bad} should not compile");
        }
        assert!(Prog::regex(&"a".repeat(200), false).is_err());
    }

    #[test]
    fn glob_compiles_to_same_engine() {
        let g = |p: &str, s: &str| Prog::glob(p, false).unwrap().is_match(s.as_bytes());
        assert!(g("ERR*full", "12:00 ERROR disk full"));
        assert!(g("d?sk", "disk"));
        assert!(!g("d?sk", "dsk"));
        assert!(g("", ""));
        assert!(g("*", "anything"));
        assert!(g(r"a\*b", "xa*by"));
        assert!(!g(r"a\*b", "axxb"));
    }
}
