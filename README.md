# logjar

Searchable compressed log archives. One static binary, no server.

logjar packs log files 20-165x smaller (typically about 2x smaller than
`xz -9`), keeps them byte-for-byte lossless, and greps them **without
decompressing them**: before decoding any line, it proves which kinds of
line *cannot* match and skips them.

```console
$ logjar pack -o hdfs.ljar HDFS.log
$ ls -lh HDFS.log hdfs.ljar
1.5G  HDFS.log
 53M  hdfs.ljar                                   # 28.8x

$ logjar grep -c --stats "blk_-1608999687919862906 " hdfs.ljar
hdfs.ljar: 268 matches in 0.77s | segments 48 (skipped 0 by index, 45 by templates) | templates 77/1103 | lines decoded 702740/11175629
268

$ gzip -dc HDFS.log.gz | grep -c "blk_-1608999687919862906 "   # the usual way: 7.9s
```

## Why

Logs pile up. You compress them to keep them, and then the one time you need
an answer you wait for `zgrep` to inflate gigabytes, or you pay for a search
cluster that holds the logs in an index bigger than the logs. logjar sits
between the two: archive-sized on disk, searchable in place, nothing to run.

The idea comes from research on log compression, mainly
[CLP](https://www.usenix.org/conference/osdi21/presentation/rodrigues)
(OSDI '21) and
[LogGrep](https://dl.acm.org/doi/10.1145/3552326.3587433) (EuroSys '23). Most
of each log line is fixed text from a `printf` somewhere. Store that text
once, store the changing values in typed columns, and both compression and
search improve. logjar is an independent implementation of the idea: an
embeddable Rust library plus a CLI, with its own file format, a pruning
algorithm based on automata, appends, live ingest and crash recovery.

## Compression

Measured with `scripts/bench.sh` on [LogHub](https://github.com/logpai/loghub)
(Zenodo record 8196385). Ratio is original size divided by compressed size;
higher is better. zstd uses the same library logjar uses, at its strongest
standard level. logjar runs at its default level (zstd 9 inside), and every
row is checked to round-trip byte for byte.

| dataset | size | gzip -9 | xz -9 | zstd -19 | **logjar** | logjar pack time |
|---|---:|---:|---:|---:|---:|---:|
| Apache | 4.9 MiB | 21.3x | 28.4x | 28.8x | **57.8x** | 0.8s |
| Linux | 2.2 MiB | 11.3x | 20.0x | 19.6x | **33.6x** | 0.3s |
| Proxifier | 2.4 MiB | 15.7x | 21.1x | 21.0x | **24.7x** | 0.4s |
| Zookeeper | 9.9 MiB | 25.9x | 29.6x | 39.0x | **165.3x** | 0.5s |
| Mac | 16.1 MiB | 11.7x | 24.5x | 26.8x | **52.5x** | 1.3s |
| HealthApp | 22.4 MiB | 11.0x | 15.7x | 16.4x | **46.3x** | 1.6s |
| HPC | 32.0 MiB | 11.2x | 19.8x | 17.0x | **35.0x** | 1.4s |
| OpenStack (normal2) | 38.6 MiB | 12.4x | 16.1x | 16.7x | **20.4x** | 1.6s |
| Hadoop | 46.3 MiB | 20.5x | 38.1x | 42.8x | **93.5x** | 1.7s |
| SSH | 70.0 MiB | 16.8x | 20.3x | 24.6x | **95.5x** | 2.0s |
<!-- BENCH-LARGE -->

Windows 11, 8 threads (the default). Pack time includes reading the input.
`-l 19` gets HDFS from 52.2 MiB down to 47.9 MiB, at about twice the pack time.

Weakest case: OpenStack, where much of each line is UUIDs and request ids
that don't repeat, so there's less structure to exploit.

## Search

Same machine, HDFS_v1 (1.5 GiB, 11.2M lines, 48 segments). All counts
checked against GNU grep.

| query | logjar | `gzip -dc \| grep` | grep, uncompressed, file cached |
|---|---:|---:|---:|
| `blk_-1608999687919862906 ` (one block id, 268 lines) | 0.9s | 7.9s | 0.2s |
| `Exception` (3,722 lines) | 0.4s | 9.2s | 0.15s |
| `PacketResponder*terminating` (1.7M lines) | 1.4s | | |
| `-E 'size [0-9]{8,}'` (3.3M lines) | 2.4s | | |
| `Exception` with `--after/--before` for one hour | 0.04s | | |

The honest summary: grepping the raw file from a warm page cache is faster
than logjar, and always will be for simple literals, since it's a memchr
over bytes already in RAM. That file takes 28x the disk, though. Against
any compressed baseline, logjar is 10-20x faster, and the more selective
the query, the bigger the gap. Queries that match most lines cost about as
much as decompressing those lines.

## Install

```sh
cargo install logjar
```

Or download a binary from the
[releases page](https://github.com/zaydmulani09/logjar/releases) (Linux
x86_64 and arm64, macOS arm64, Windows x86_64).

## Use

```sh
logjar pack -o app.ljar /var/log/app/*.log    # .gz inputs are detected and decompressed
logjar pack -a -o app.ljar new.log             # append; continues existing streams
logjar ls app.ljar                             # streams, lines, sizes

logjar grep "Failed*retries" app.ljar          # glob: * any run, ? any byte
logjar grep -E '(WARN|ERROR) .*timeout' app.ljar
logjar grep -i -n -e OOM -e "out of memory" app.ljar
logjar grep --after 2026-11-01 --before 2026-11-02T06:00 "disk full" app.ljar
logjar grep --json -m 100 -E ' 5[0-9]{2} ' app.ljar  # {"stream","line","time_ns","text"}

logjar cat -s worker.log --after 2026-11-01T12:00 app.ljar
logjar unpack -C restored/ app.ljar            # the exact original files

tail -F app.log | logjar ingest -o live.ljar   # stays searchable while it grows
logjar compact live.ljar                       # merge ingest's small segments

logjar templates app.ljar                      # the distinct line shapes, by frequency
logjar stats app.ljar                          # where the bytes go
logjar verify app.ljar                         # decode everything, check checksums
```

`grep` follows grep's conventions: exit status 0 if anything matched, 1 if
nothing, 2 on error. Lines are prefixed with the stream name when more than
one stream is searched.

### As a library

```rust
use logjar::{Archive, Options, Query, Writer};

let mut w = Writer::create("app.ljar", Options::default())?;
w.add_stream("app.log", std::io::BufReader::new(std::fs::File::open("app.log")?))?;
w.finish()?;

let archive = Archive::open("app.ljar")?;
let q = Query::regex(r"after \d+ retries")?.after(Query::parse_time("2026-11-01")?);
archive.search(&q, &[], |m| {
    println!("{}:{}", m.line_number, String::from_utf8_lossy(&m.line));
    true // false stops the search
})?;
```

`default-features = false` drops the CLI dependencies (clap, flate2) and
leaves `zstd` and `crc32fast`.

## How it works

Each line is split into an optional timestamp, a **template** (the static
text, with typed holes) and **variables**:

```text
081109 203615 148 INFO dfs.DataNode$PacketResponder: Received block blk_-1608999687919862906 of size 91178 from /10.250.10.6
template:   <int> INFO dfs.DataNode$PacketResponder: Received block <var> of size <int> from /<var>
variables:  148, blk_-1608999687919862906, 91178, 10.250.10.6
```

HDFS's 11.2 million lines use 65 templates. Lines are grouped into segments
(32 MiB of input by default). Each segment stores its templates, a
dictionary of non-numeric variables, and every variable column grouped by
template and slot, delta-coded where that helps, in separately compressed
zstd blocks.

Search prunes at three levels:

1. **Footer index.** Each segment's stream and time range. A time window or
   stream filter skips segments without reading them.
2. **Templates.** The query compiles to a position automaton. Running it
   over a template symbolically (an `<int>` hole is "one or more of
   `[-0-9]`", a `<var>` hole is "any of this segment's dictionary entries")
   finds every state a real line could reach. If no accepting state is
   reachable, no line of that template can match, so it's skipped. If all
   are skipped, so is the segment, having only inflated two small blocks.
3. **Lines.** Only lines of surviving templates are rebuilt and checked
   exactly.

Pruning only ever over-approximates, so it can't hide a match. That
property is tested directly on random templates and end to end against a
naive scan with random globs, regexes, time windows and appends.

More detail: [docs/DESIGN.md](docs/DESIGN.md). The file format is
specified in [docs/FORMAT.md](docs/FORMAT.md).

## Durability

Archives are append-only. Every segment block carries a zstd checksum; the
footer carries a CRC32. An interrupted write leaves the previous footer
intact and readers fall back to it, so a crash loses at most what was
written since the last checkpoint (`ingest` checkpoints every 5 seconds or
32 MiB by default). `logjar verify` decodes everything and checks every
checksum.

## Limits

* Segment dictionaries are not shared, so an id that recurs across segments
  is stored once per segment.
* JSON and other structured logs work, but every key order becomes its own
  template; there's no schema-aware encoding.
* No index on variable values: searching for a rare number still decodes
  every line of the templates where it could appear.
* Regexes are limited to 127 positions after expanding counted repetition;
  `^` and `$` only at the very start and end. No backreferences or
  lookaround (pruning needs a regular language).
* Timestamps without a zone are treated as UTC; `%z` offsets stay in the
  message, losslessly, but aren't indexed.

## License

MIT
