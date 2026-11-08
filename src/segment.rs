//! A segment is a self-contained, columnar chunk of one stream's lines.
//!
//! Each segment has its own template table and variable dictionary, so it
//! can be decoded, searched or skipped on its own. Its bytes are five
//! independently compressed blocks:
//!
//! | block    | contents                                                    |
//! |----------|-------------------------------------------------------------|
//! | `meta`   | timestamp specs, templates, per-template row counts/offsets |
//! | `dict`   | dictionary variables                                        |
//! | `events` | template id of each line, in order                          |
//! | `times`  | timestamp spec of each line, then value deltas              |
//! | `vars`   | variables grouped by template, then slot, then row          |
//!
//! Grouping variables by (template, slot) puts values of the same field next
//! to each other (all the block sizes, all the ports), which is where most
//! of the compression over plain zstd comes from. It also lets search read
//! `meta` and `dict` first and skip the segment without touching the big
//! blocks when no template can match.

use std::collections::HashMap;

use crate::message::{self, Kind, Var};
use crate::timestamp::{self, Spec};
use crate::varint::{self, Cursor};
use crate::{Error, Result};

pub const BLOCKS: usize = 5;
pub const BLOCK_NAMES: [&str; BLOCKS] = ["meta", "dict", "events", "times", "vars"];
const META: usize = 0;
const DICT: usize = 1;
const EVENTS: usize = 2;
const TIMES: usize = 3;
const VARS: usize = 4;

/// Refuse to inflate a block beyond this; guards against corrupt lengths.
const MAX_BLOCK: usize = 1 << 31;

#[derive(Default)]
struct TemplateCols {
    bytes: Vec<u8>,
    rows: u64,
    /// One column per slot. Floats take two entries per row.
    cols: Vec<Vec<u64>>,
}

/// Accumulates lines for one segment.
pub struct Builder {
    stream: u32,
    templates: Vec<TemplateCols>,
    tpl_ids: HashMap<Vec<u8>, u32>,
    dict: Vec<Vec<u8>>,
    dict_ids: HashMap<Vec<u8>, u32>,
    events: Vec<u32>,
    /// (local spec id + 1, native value); 0 means no timestamp.
    times: Vec<(u32, i64)>,
    /// builtin spec index -> local id + 1
    spec_ids: HashMap<usize, u32>,
    specs: Vec<usize>,
    hint: usize,
    raw_bytes: usize,
    time_range: Option<(i64, i64)>,
    tpl_buf: Vec<u8>,
}

impl Builder {
    pub fn new(stream: u32) -> Builder {
        Builder {
            stream,
            templates: Vec::new(),
            tpl_ids: HashMap::new(),
            dict: Vec::new(),
            dict_ids: HashMap::new(),
            events: Vec::new(),
            times: Vec::new(),
            spec_ids: HashMap::new(),
            specs: Vec::new(),
            hint: 0,
            raw_bytes: 0,
            time_range: None,
            tpl_buf: Vec::new(),
        }
    }

    /// Adds one line, without its trailing `\n`.
    pub fn push(&mut self, line: &[u8]) {
        self.raw_bytes += line.len() + 1;
        let builtin = timestamp::builtin();
        let (ts, msg) = match timestamp::detect_with(builtin, self.hint, line) {
            Some((i, v, n)) => {
                self.hint = i;
                let next = self.specs.len() as u32 + 1;
                let id = *self.spec_ids.entry(i).or_insert(next);
                if id == next {
                    self.specs.push(i);
                }
                let spec = &builtin[i];
                if spec.has_year {
                    let ns = spec.to_nanos(v);
                    self.time_range = Some(match self.time_range {
                        Some((lo, hi)) => (lo.min(ns), hi.max(ns)),
                        None => (ns, ns),
                    });
                }
                ((id, v), &line[n..])
            }
            None => ((0, 0), line),
        };
        self.times.push(ts);

        let mut vars = Vec::new();
        self.tpl_buf.clear();
        message::encode(msg, &mut self.tpl_buf, &mut vars);
        let tid = match self.tpl_ids.get(&self.tpl_buf[..]) {
            Some(&t) => t,
            None => {
                let t = self.templates.len() as u32;
                let slots = message::slots(&self.tpl_buf).expect("fresh template is well formed");
                self.templates.push(TemplateCols {
                    bytes: self.tpl_buf.clone(),
                    cols: vec![Vec::new(); slots.len()],
                    rows: 0,
                });
                self.tpl_ids.insert(self.tpl_buf.clone(), t);
                t
            }
        };
        self.events.push(tid);
        let tc = &mut self.templates[tid as usize];
        tc.rows += 1;
        for (col, v) in tc.cols.iter_mut().zip(vars) {
            match v {
                Var::Int(i) => col.push(varint::zigzag(i)),
                Var::Float(value, meta) => {
                    col.push(value);
                    col.push(meta);
                }
                Var::Dict(d) => {
                    let next = self.dict.len() as u32;
                    let id = match self.dict_ids.get(d) {
                        Some(&id) => id,
                        None => {
                            self.dict.push(d.to_vec());
                            self.dict_ids.insert(d.to_vec(), next);
                            next
                        }
                    };
                    col.push(id as u64);
                }
            }
        }
    }

    /// Serializes and compresses the segment.
    pub fn finish(self, level: i32) -> Result<Encoded> {
        let builtin = timestamp::builtin();
        let mut raw: [Vec<u8>; BLOCKS] = Default::default();

        let mut vars = Vec::new();
        let m = &mut raw[META];
        varint::put_u64(m, self.specs.len() as u64);
        for &i in &self.specs {
            varint::put_bytes(m, builtin[i].text.as_bytes());
        }
        varint::put_u64(m, self.templates.len() as u64);
        for t in &self.templates {
            varint::put_bytes(m, &t.bytes);
            varint::put_u64(m, t.rows);
            varint::put_u64(m, vars.len() as u64);
            for col in &t.cols {
                for &v in col {
                    varint::put_u64(&mut vars, v);
                }
            }
        }
        raw[VARS] = vars;

        varint::put_u64(&mut raw[DICT], self.dict.len() as u64);
        for d in &self.dict {
            varint::put_bytes(&mut raw[DICT], d);
        }
        for &e in &self.events {
            varint::put_u64(&mut raw[EVENTS], e as u64);
        }
        let mut prev = 0i64;
        for &(s, _) in &self.times {
            varint::put_u64(&mut raw[TIMES], s as u64);
        }
        for &(s, v) in &self.times {
            if s != 0 {
                varint::put_i64(&mut raw[TIMES], v.wrapping_sub(prev));
                prev = v;
            }
        }

        let mut bytes = Vec::new();
        let mut dir = Vec::new();
        let mut body = Vec::new();
        for block in &raw {
            let c = zstd::bulk::compress(block, level)?;
            varint::put_u64(&mut dir, block.len() as u64);
            varint::put_u64(&mut dir, c.len() as u64);
            body.extend_from_slice(&c);
        }
        varint::put_u64(&mut bytes, dir.len() as u64);
        bytes.extend_from_slice(&dir);
        bytes.extend_from_slice(&body);
        Ok(Encoded {
            bytes,
            stream: self.stream,
            lines: self.events.len() as u64,
            raw_bytes: self.raw_bytes as u64,
            time_range: self.time_range,
        })
    }
}

/// A compressed segment ready to be written, with the facts the archive
/// index keeps about it.
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub stream: u32,
    pub lines: u64,
    pub raw_bytes: u64,
    pub time_range: Option<(i64, i64)>,
}

/// Decoded `meta` block.
pub struct Meta {
    pub specs: Vec<Spec>,
    pub templates: Vec<Template>,
}

pub struct Template {
    pub bytes: Vec<u8>,
    pub slots: Vec<Kind>,
    pub rows: u64,
    pub var_offset: usize,
}

/// A compressed segment read back from an archive. Blocks are inflated
/// only when asked for.
pub struct Segment {
    bytes: Vec<u8>,
    /// (start, compressed len, raw len) per block.
    blocks: [(usize, usize, usize); BLOCKS],
}

impl Segment {
    pub fn parse(bytes: Vec<u8>) -> Result<Segment> {
        let mut c = Cursor::new(&bytes);
        let dir_len = c.usize()?;
        let mut d = Cursor::new(c.take(dir_len)?);
        let mut start = c.pos();
        let mut blocks = [(0, 0, 0); BLOCKS];
        for b in &mut blocks {
            let raw = d.usize()?;
            let len = d.usize()?;
            if raw > MAX_BLOCK {
                return Err(Error::Corrupt("block too large"));
            }
            *b = (start, len, raw);
            start = start
                .checked_add(len)
                .ok_or(Error::Corrupt("block offset"))?;
        }
        if start > bytes.len() {
            return Err(Error::Corrupt("segment truncated"));
        }
        Ok(Segment { bytes, blocks })
    }

    fn inflate(&self, i: usize) -> Result<Vec<u8>> {
        let (start, len, raw) = self.blocks[i];
        let out = zstd::bulk::decompress(&self.bytes[start..start + len], raw)
            .map_err(|_| Error::Corrupt("zstd block"))?;
        if out.len() != raw {
            return Err(Error::Corrupt("block length"));
        }
        Ok(out)
    }

    pub fn meta(&self) -> Result<Meta> {
        let raw = self.inflate(META)?;
        let mut c = Cursor::new(&raw);
        let n = c.usize()?;
        let mut specs = Vec::with_capacity(n.min(256));
        for _ in 0..n {
            let s = std::str::from_utf8(c.bytes()?).map_err(|_| Error::Corrupt("spec utf8"))?;
            specs.push(Spec::new(s));
        }
        let n = c.usize()?;
        let mut templates = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            let bytes = c.bytes()?.to_vec();
            let slots = message::slots(&bytes)?;
            templates.push(Template {
                bytes,
                slots,
                rows: c.u64()?,
                var_offset: c.usize()?,
            });
        }
        Ok(Meta { specs, templates })
    }

    pub fn dict(&self) -> Result<Vec<Vec<u8>>> {
        let raw = self.inflate(DICT)?;
        let mut c = Cursor::new(&raw);
        let n = c.usize()?;
        let mut out = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            out.push(c.bytes()?.to_vec());
        }
        Ok(out)
    }

    pub fn events(&self) -> Result<Vec<u32>> {
        let raw = self.inflate(EVENTS)?;
        let mut c = Cursor::new(&raw);
        let mut out = Vec::new();
        while !c.is_empty() {
            out.push(u32::try_from(c.u64()?).map_err(|_| Error::Corrupt("template id"))?);
        }
        Ok(out)
    }

    /// (spec id + 1, native value) per line; 0 means none.
    pub fn times(&self, lines: usize) -> Result<Vec<(u32, i64)>> {
        let raw = self.inflate(TIMES)?;
        let mut c = Cursor::new(&raw);
        let mut out = Vec::with_capacity(lines);
        for _ in 0..lines {
            out.push((
                u32::try_from(c.u64()?).map_err(|_| Error::Corrupt("spec id"))?,
                0,
            ));
        }
        let mut prev = 0i64;
        for t in &mut out {
            if t.0 != 0 {
                prev = prev.wrapping_add(c.i64()?);
                t.1 = prev;
            }
        }
        Ok(out)
    }

    pub fn vars(&self) -> Result<Vec<u8>> {
        self.inflate(VARS)
    }

    /// (raw, compressed) size of each block, in [`BLOCK_NAMES`] order.
    pub fn block_sizes(&self) -> [(usize, usize); BLOCKS] {
        self.blocks.map(|(_, len, raw)| (raw, len))
    }
}

/// Reads one template's variables out of the `vars` block: one column per
/// slot, floats as (value, meta) pairs.
pub fn template_columns(vars: &[u8], t: &Template) -> Result<Vec<Vec<u64>>> {
    let mut c = Cursor::new(
        vars.get(t.var_offset..)
            .ok_or(Error::Corrupt("var offset"))?,
    );
    let rows = usize::try_from(t.rows).map_err(|_| Error::Corrupt("rows"))?;
    t.slots
        .iter()
        .map(|k| {
            let n = if *k == Kind::Float { rows * 2 } else { rows };
            (0..n).map(|_| c.u64()).collect()
        })
        .collect()
}

/// Rebuilds one line from its template and the row's variables.
pub fn write_line(
    tpl: &Template,
    cols: &[Vec<u64>],
    row: usize,
    dict: &[Vec<u8>],
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut slot = 0;
    let mut i = 0;
    let b = &tpl.bytes;
    while i < b.len() {
        match b[i] {
            message::ESC => {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            message::PH_INT | message::PH_FLOAT | message::PH_DICT => {
                let col = cols.get(slot).ok_or(Error::Corrupt("slot"))?;
                let get = |j: usize| col.get(j).copied().ok_or(Error::Corrupt("row"));
                let var = match tpl.slots[slot] {
                    Kind::Int => Var::Int(varint::unzigzag(get(row)?)),
                    Kind::Float => Var::Float(get(row * 2)?, get(row * 2 + 1)?),
                    Kind::Dict => Var::Dict(
                        dict.get(get(row)? as usize)
                            .ok_or(Error::Corrupt("dict id"))?,
                    ),
                };
                message::write_var(&var, out)?;
                slot += 1;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Ok(())
}

/// Fully decodes a segment, calling `f` with each line (no newline).
pub fn decode_all(
    seg: &Segment,
    lines: usize,
    mut f: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let meta = seg.meta()?;
    let dict = seg.dict()?;
    let events = seg.events()?;
    let times = seg.times(lines)?;
    let vars = seg.vars()?;
    if events.len() != lines {
        return Err(Error::Corrupt("line count"));
    }
    let mut cols: Vec<Option<Vec<Vec<u64>>>> = (0..meta.templates.len()).map(|_| None).collect();
    let mut cursor = vec![0usize; meta.templates.len()];
    let mut line = Vec::new();
    for (e, &(spec, value)) in events.iter().zip(&times) {
        let t = *e as usize;
        let tpl = meta.templates.get(t).ok_or(Error::Corrupt("template id"))?;
        line.clear();
        if spec != 0 {
            let s = meta
                .specs
                .get(spec as usize - 1)
                .ok_or(Error::Corrupt("spec id"))?;
            timestamp::format(s, value, &mut line)?;
        }
        if cols[t].is_none() {
            cols[t] = Some(template_columns(&vars, tpl)?);
        }
        write_line(tpl, cols[t].as_ref().unwrap(), cursor[t], &dict, &mut line)?;
        cursor[t] += 1;
        f(&line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_roundtrip() {
        let lines: Vec<&[u8]> = vec![
            b"2015-10-18 18:01:47,978 INFO [main] Created MRAppMaster for application appattempt_1445144423722_0020_000001",
            b"2015-10-18 18:01:48,963 INFO [main] Executing with tokens:",
            b"2015-10-18 18:01:48,963 INFO [main] Kind: YARN_AM_RM_TOKEN, Service: , Ident: (appAttemptId { application_id { id: 20 cluster_timestamp: 1445144423722 } attemptId: 1 } keyId: -127633188)",
            b"no timestamp here, value=3.14 and -0.5",
            b"",
            b"2015-10-18 18:01:49,228 INFO [main] Using mapred newApiCommitter.",
        ];
        let mut b = Builder::new(0);
        for l in &lines {
            b.push(l);
        }
        let enc = b.finish(3).unwrap();
        assert_eq!(enc.lines, 6);
        let seg = Segment::parse(enc.bytes).unwrap();
        let mut got = Vec::new();
        decode_all(&seg, 6, |l| {
            got.push(l.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(got, lines.iter().map(|l| l.to_vec()).collect::<Vec<_>>());
    }

    #[test]
    fn corrupt_segment_is_error() {
        let mut b = Builder::new(0);
        b.push(b"hello 1");
        let mut bytes = b.finish(3).unwrap().bytes;
        let n = bytes.len();
        bytes[n - 3] ^= 0xff;
        let res = Segment::parse(bytes).and_then(|s| decode_all(&s, 1, |_| Ok(())));
        assert!(res.is_err());
        assert!(Segment::parse(vec![0x05, 1]).is_err());
    }
}
