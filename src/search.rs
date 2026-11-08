//! Running a [`Query`] over an archive, segment by segment.
//!
//! Work is skipped at three levels, cheapest first:
//! 1. the footer index: stream filter and segment time range;
//! 2. the segment's templates (and, if needed, its dictionary): see
//!    [`crate::query`];
//! 3. lines of templates that cannot match are never reconstructed.
//!
//! Surviving lines are rebuilt and checked with the exact glob matcher.

use std::collections::HashMap;

use crate::archive::Archive;
use crate::message::{self, Kind};
use crate::query::{DictStates, Nfa, Query};
use crate::segment::{self, Segment};
use crate::{timestamp, Error, Result};

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub stream: u32,
    /// 1-based line number within the stream.
    pub line_number: u64,
    /// Nanoseconds since the Unix epoch, if the line has a dated timestamp.
    pub timestamp: Option<i64>,
    /// The original line, without its newline.
    pub line: Vec<u8>,
}

/// Where a search spent (and saved) its effort.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchStats {
    pub segments: u64,
    /// Ruled out by stream or time range from the footer alone.
    pub segments_skipped_index: u64,
    /// Read, but no template could match, so only `meta`/`dict` were inflated.
    pub segments_skipped_templates: u64,
    pub templates: u64,
    pub templates_matched: u64,
    pub lines_total: u64,
    /// Lines actually reconstructed and checked.
    pub lines_decoded: u64,
    pub matches: u64,
}

impl SearchStats {
    fn add(&mut self, o: &SearchStats) {
        self.segments += o.segments;
        self.segments_skipped_index += o.segments_skipped_index;
        self.segments_skipped_templates += o.segments_skipped_templates;
        self.templates += o.templates;
        self.templates_matched += o.templates_matched;
        self.lines_total += o.lines_total;
        self.lines_decoded += o.lines_decoded;
        self.matches += o.matches;
    }
}

impl Archive {
    /// Calls `f` with every matching line, in archive order. `f` returns
    /// `false` to stop early. `streams` limits the search to those stream
    /// ids (empty = all).
    pub fn search(&self, q: &Query, streams: &[u32], mut f: impl FnMut(Match) -> bool) -> Result<SearchStats> {
        let mut total = SearchStats::default();
        for (i, base) in self.line_bases().into_iter().enumerate() {
            let (matches, stats) = self.search_segment(i, base, q, streams)?;
            total.add(&stats);
            for m in matches {
                if !f(m) {
                    return Ok(total);
                }
            }
        }
        Ok(total)
    }

    /// First line number (0-based, within its stream) of each segment.
    pub(crate) fn line_bases(&self) -> Vec<u64> {
        let mut next = vec![0u64; self.index().streams.len()];
        self.index()
            .segments
            .iter()
            .map(|s| {
                let b = next[s.stream as usize];
                next[s.stream as usize] += s.lines;
                b
            })
            .collect()
    }

    pub(crate) fn search_segment(
        &self,
        i: usize,
        line_base: u64,
        q: &Query,
        streams: &[u32],
    ) -> Result<(Vec<Match>, SearchStats)> {
        let info = &self.index().segments[i];
        let mut st = SearchStats { segments: 1, lines_total: info.lines, ..Default::default() };
        let in_window = match info.time_range {
            _ if !q.has_time_filter() => true,
            Some((lo, hi)) => q.range_ok(lo, hi),
            None => false,
        };
        if !in_window || !(streams.is_empty() || streams.contains(&info.stream)) {
            st.segments_skipped_index = 1;
            return Ok((Vec::new(), st));
        }

        let seg = self.read_segment(i)?;
        let meta = seg.meta()?;
        st.templates = meta.templates.len() as u64;
        let mut dict: Option<Vec<Vec<u8>>> = None;
        let candidates: Vec<bool> = match Nfa::new(q, &meta.specs).filter(|_| !q.matches_everything()) {
            None => vec![true; meta.templates.len()],
            Some(nfa) => {
                let mut out = Vec::with_capacity(meta.templates.len());
                let mut coarse = Vec::new();
                for t in &meta.templates {
                    let pieces = message::pieces(&t.bytes)?;
                    let ok = nfa.template_may_match(&pieces, None);
                    out.push(ok);
                    coarse.push(pieces);
                }
                // Refine survivors that have dictionary slots against the
                // segment's real dictionary values.
                let needs_dict = meta.templates.iter().zip(&out).any(|(t, &ok)| ok && t.slots.contains(&Kind::Dict));
                if needs_dict {
                    let d = dict.insert(seg.dict()?);
                    let mut states = DictStates::new(d);
                    for (j, t) in meta.templates.iter().enumerate() {
                        if out[j] && t.slots.contains(&Kind::Dict) {
                            out[j] = nfa.template_may_match(&coarse[j], Some(&mut states));
                        }
                    }
                }
                out
            }
        };
        st.templates_matched = candidates.iter().filter(|&&c| c).count() as u64;
        if st.templates_matched == 0 {
            st.segments_skipped_templates = 1;
            return Ok((Vec::new(), st));
        }

        let dict = match dict {
            Some(d) => d,
            None => seg.dict()?,
        };
        let matches = decode_candidates(&seg, info.lines as usize, &meta, &dict, &candidates, |line_no, ts, line| {
            st.lines_decoded += 1;
            if q.has_time_filter() && !ts.is_some_and(|ns| q.time_ok(ns)) {
                return None;
            }
            q.is_match(line).then(|| Match {
                stream: info.stream,
                line_number: line_base + line_no as u64 + 1,
                timestamp: ts,
                line: line.to_vec(),
            })
        })?;
        st.matches = matches.len() as u64;
        Ok((matches, st))
    }

    /// Every distinct template in the archive with its line count, most
    /// common first. Reads only the `meta` blocks.
    pub fn templates(&self) -> Result<Vec<(String, u64)>> {
        let mut counts: HashMap<Vec<u8>, u64> = HashMap::new();
        for i in 0..self.index().segments.len() {
            for t in self.read_segment(i)?.meta()?.templates {
                *counts.entry(t.bytes).or_default() += t.rows;
            }
        }
        let mut out = counts
            .into_iter()
            .map(|(b, n)| Ok((message::render(&b)?, n)))
            .collect::<Result<Vec<_>>>()?;
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(out)
    }
}

/// Reconstructs only lines whose template is a candidate, passing
/// `(index in segment, timestamp ns, line)` to `keep`.
fn decode_candidates<T>(
    seg: &Segment,
    lines: usize,
    meta: &segment::Meta,
    dict: &[Vec<u8>],
    candidates: &[bool],
    mut keep: impl FnMut(usize, Option<i64>, &[u8]) -> Option<T>,
) -> Result<Vec<T>> {
    let events = seg.events()?;
    let times = seg.times(lines)?;
    let vars = seg.vars()?;
    if events.len() != lines {
        return Err(Error::Corrupt("line count"));
    }
    let mut cols: Vec<Option<Vec<Vec<u64>>>> = (0..meta.templates.len()).map(|_| None).collect();
    let mut cursor = vec![0usize; meta.templates.len()];
    let mut out = Vec::new();
    let mut line = Vec::new();
    for (n, (&e, &(spec, value))) in events.iter().zip(&times).enumerate() {
        let t = e as usize;
        if !*candidates.get(t).ok_or(Error::Corrupt("template id"))? {
            continue;
        }
        let tpl = &meta.templates[t];
        line.clear();
        let mut ts = None;
        if spec != 0 {
            let s = meta.specs.get(spec as usize - 1).ok_or(Error::Corrupt("spec id"))?;
            timestamp::format(s, value, &mut line)?;
            ts = s.has_year.then(|| s.to_nanos(value));
        }
        if cols[t].is_none() {
            cols[t] = Some(segment::template_columns(&vars, tpl)?);
        }
        segment::write_line(tpl, cols[t].as_ref().unwrap(), cursor[t], dict, &mut line)?;
        cursor[t] += 1;
        if let Some(m) = keep(n, ts, &line) {
            out.push(m);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Writer};

    #[test]
    fn search_matches_naive_scan() {
        let p = std::env::temp_dir().join(format!("logjar-search-{}.ljar", std::process::id()));
        let mut text = String::new();
        for i in 0..5000 {
            let ts = format!("2015-10-18 18:{:02}:{:02},{:03}", (i / 60) % 60, i % 60, i % 1000);
            let line = match i % 7 {
                0 => format!("{ts} ERROR [main] Failed to fetch blk_{} after {} retries", i * 31 % 997, i % 5),
                1 => format!("{ts} INFO Received block blk_{} of size {} from /10.0.{}.{}", i, 1 << (i % 27), i % 256, i % 7),
                2 => format!("{ts} WARN GC pause {}.{:03} ms", i % 300, i % 1000),
                3 => format!("plain line without timestamp #{i}"),
                _ => format!("{ts} INFO heartbeat ok node-{:x}", i % 64),
            };
            text.push_str(&line);
            text.push('\n');
        }
        let mut w = Writer::create(&p, Options { segment_lines: 700, ..Options::default() }).unwrap();
        w.add_stream("app.log", text.as_bytes()).unwrap();
        w.finish().unwrap();
        let a = Archive::open(&p).unwrap();

        let queries = [
            "ERROR", "blk_42 ", "blk_42", "size 4096 ", "GC pause 1?.0", "node-3f", "#4999",
            "18:05:0", "10.0.9.", "*retries", "nothing-like-this", "Received*from /10.0.1.1", "",
        ];
        for pat in queries {
            for ic in [false, true] {
                let q = Query::new(pat).unwrap().ignore_case(ic);
                let mut got = Vec::new();
                let stats = a.search(&q, &[], |m| {
                    got.push(m.line_number);
                    true
                })
                .unwrap();
                let want: Vec<u64> = text
                    .lines()
                    .enumerate()
                    .filter(|(_, l)| q.is_match(l.as_bytes()))
                    .map(|(n, _)| n as u64 + 1)
                    .collect();
                assert_eq!(got, want, "query {pat:?} ic={ic}");
                assert_eq!(stats.matches, want.len() as u64);
            }
        }

        // Selective queries skip work.
        let q = Query::new("nothing-like-this").unwrap();
        let st = a.search(&q, &[], |_| true).unwrap();
        assert_eq!(st.lines_decoded, 0);
        assert_eq!(st.segments_skipped_templates, st.segments);

        // Time window.
        let q = Query::new("ERROR")
            .unwrap()
            .after(Query::parse_time("2015-10-18 18:10").unwrap())
            .before(Query::parse_time("2015-10-18 18:20").unwrap());
        let mut n = 0;
        a.search(&q, &[], |m| {
            let l = String::from_utf8(m.line).unwrap();
            assert!(l.as_str() >= "2015-10-18 18:10" && l.as_str() < "2015-10-18 18:20", "{l}");
            n += 1;
            true
        })
        .unwrap();
        assert!(n > 0);
    }
}
