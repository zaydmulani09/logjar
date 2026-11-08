# Changelog

## 0.1.0

First release.

- `.ljar` archive format, version 1 (see `docs/FORMAT.md`): template and
  variable encoding, typed and delta-coded columns, per-segment zstd blocks
  with checksums, footer index with stream and time ranges, appends.
- Lossless round trips: CRLF, invalid UTF-8 and a missing final newline
  survive byte for byte.
- Search with three levels of pruning (footer index, symbolic template
  matching, then exact line checks). Globs and byte-oriented regexes share
  one automaton engine.
- Leading timestamps are recognized in 49 built-in formats and indexed, so
  `--after`/`--before` skip whole segments.
- CLI: `pack` (gzip inputs, wildcards, directories), `ingest` with
  checkpoints, `compact`, `unpack`, `cat`, `ls`, `grep` (grep-style flags,
  `-E`, `--json`, `--stats`), `verify`, `stats`, `templates`.
- Crash recovery: readers fall back to the newest footer that verifies.
- Library API: `Writer`, `Archive`, `Query`, `StreamReader`.
