# Design

logjar answers one question: how do you keep months of logs small *and*
still grep them in seconds? General-purpose compressors make you pick one.
gzip and zstd shrink logs well but must be decompressed end to end before
any search; full-text indexes (Elasticsearch, Loki's chunks plus labels)
search fast but cost memory, servers and often more disk than the logs.

The approach comes from the research line on searchable log compression,
chiefly CLP (Rodrigues et al., OSDI '21) and LogGrep (Wei et al., EuroSys '23):
most of a log line is static text written by a `printf` somewhere, and the
rest is a handful of variables. Separate the two and both compression and
search get easier. logjar is an independent implementation of that idea as
an embeddable Rust library and a single static binary, with its own archive
format, search algorithm and append model.

## Encoding

Each line is split into a timestamp, a template and variables
(see [FORMAT.md](FORMAT.md) for exact rules):

```text
081109 203615 148 INFO dfs.DataNode$PacketResponder: Received block blk_-1608999687919862906 of size 91178 from /10.250.10.6
└─timestamp─┘ └───────────────── template: "<int> INFO dfs.DataNode$PacketResponder: Received block <var> of size <int> from /<var>"
                variables: 148, "blk_-1608999687919862906", 91178, "10.250.10.6"
```

HDFS_v1's 11.2 million lines use 65 distinct templates. Instead of storing
the static text 11.2 million times, each line stores a template id.

Variables are then laid out by **(template, slot)**: all the block sizes of
template 4 together, then all its source addresses, and so on. Values of one
field look alike (similar magnitudes, shared prefixes), which is exactly what
zstd's entropy coder and match finder like. Integer and dictionary columns
can also switch to delta coding, which turns ascending counters and the
"burst of lines about the same block" pattern into small numbers.

Timestamps are parsed with a small format language and stored as deltas in
the format's native unit (milliseconds for `,%3`). A parse only counts if
formatting the value back gives the identical bytes, so odd inputs
(wrong weekday, leap second, unusual padding) just stay in the message.
Lossless round trips are a hard requirement, tested with byte-level fuzzing
and on every benchmark dataset.

### Segments

Lines are grouped into segments (32 MiB of input by default). Each segment
is self-contained: its own template table, dictionary and columns, in five
separately compressed blocks. That costs a little compression (a variable
that recurs across segments is stored once per segment) and buys:

* **parallelism**: segments encode and search independently on all cores;
* **cheap skipping**: the small `meta` and `dict` blocks can be read without
  inflating the large ones;
* **appendability**: new data is new segments plus a new footer; nothing
  already written changes;
* **bounded memory**: a writer holds one segment per thread.

On HDFS_v1, 8 / 32 / 128 MiB segments give 23.0x / 25.8x / 29.1x before
delta coding; 32 MiB is the default to keep memory near 1 GiB with 8
threads. `--segment-mb` changes it.

## Search

A query is a glob (`*`, `?`, `\` escapes) or a regular expression, matched
against any substring of a line (regexes may anchor with `^`/`$`). Results are always checked on the reconstructed line, so they are
exact. The work is in not reconstructing lines.

**Level 1: the footer.** Each segment records its stream and its timestamp
range. A stream filter or a time window rules segments out without reading
them.

**Level 2: templates.** For each template in a surviving segment, logjar
proves whether *any* line of that template could match, using only the
template text. The pattern becomes a Glushkov position automaton: one bit
per pattern position, a 256-entry table of which positions accept each
byte, and a follow set per position. Globs compile to the same automaton
(`*` is `.*`), so there is one pruning path. The template becomes a
sequence of symbols:

* literal text: one exact byte each;
* an integer slot: one or more bytes from `[-0-9]`;
* a float slot: one or more bytes from `[-.0-9]`;
* a dictionary slot: any of the segment's dictionary entries;
* the optional leading timestamp: zero or more bytes from the alphabet of
  the segment's timestamp formats.

Running the automaton over that sequence computes, in one pass, every
pattern position some real line could reach. A character-class slot is a
fixpoint of "step on any byte in the class": the class collapses to one
mask of positions, so each iteration is a follow-set union and an AND on a
`u128`, with at most pattern-length iterations. A dictionary slot is the
union of running the automaton over each entry, memoized per input state
set, so a segment's dictionary is scanned at most once per distinct state.
A match can end partway through any symbol, so acceptance is checked after
every byte of literal text and dictionary values, not only at symbol ends.

Anchors need care around the optional timestamp: `^` must be able to match
both before and after it, so the start-of-line flag stays set until the
first template symbol. An end anchor requires the final state set to
accept.

If the accept bit is unreachable, no line of that template can match. Every
step over-approximates the real lines and never under-approximates, so a
template is only skipped when it truly has no matches. This soundness
property is tested directly on random lines and patterns, and end to end by
a differential test against a naive scan.

Templates are checked twice: first with dictionary slots treated as their
character class (cheap: no dictionary needed), then, only for survivors
that contain dictionary slots, against the real dictionary. A query for one
block id skips every segment whose dictionary doesn't contain a fitting
entry, having inflated only `meta` and `dict`.

**Level 3: lines.** Only lines whose template survived are reconstructed
and checked. Their variable columns are decoded lazily, per template.

Example: `logjar grep "blk_-1608999687919862906 "` over HDFS_v1 (1.5 GiB,
48 segments) skips 45 segments outright, and the stats line shows exactly
how much was skipped and why.

### Alternatives and inversion

`-e A -e B` builds one automaton per pattern; a template survives if any
accepts. A pattern that matches the empty string matches every line, which
turns pruning off. `-v` cannot prune (a template that can't match is precisely what
it wants), so it decodes everything and negates the check.

## Durability and appends

The trailer at end of file names the live footer, which carries a CRC32.
Each block carries zstd's content checksum. `Writer::checkpoint` writes a
footer without closing, which is how `logjar ingest` stays searchable and
crash-safe while a log grows: a reader (or a crash) sees the archive as of
the last checkpoint. Recovery scans backwards in 1 MiB windows for the
newest trailer that verifies, so opening an archive while a writer is
mid-segment costs one or two small reads, not a full scan.

## What it doesn't do (yet)

* **Global dictionaries.** Dictionaries are per segment, so recurring
  variables are stored once per segment. A shared dictionary would improve
  compression on long-lived ids at the cost of segment independence.
* **Structured logs.** JSON lines compress fine, but each distinct key order
  is a template and values are tokenized as text. A schema-aware encoding
  (as in CLP-S) would do much better.
* **Big regexes.** A pattern gets at most 127 positions (one `u128`), and
  `^`/`$` only work at the very start and end. Counted repetition is
  expanded, so `\d{60}` costs 60 positions.
* **Variable-level indexes.** A query for a rare integer value still decodes
  every line of the templates where it could occur. Per-column min/max or
  bloom filters would skip those too.
* **Zones.** Timestamps without an offset are treated as UTC; `%z` offsets
  aren't parsed (they stay in the message, losslessly).
