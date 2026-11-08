use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use logjar::{Archive, Options, Query, Writer};

#[derive(Parser)]
#[command(name = "logjar", version, about = "Searchable compressed log archives")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compress log files into an archive (`-` reads stdin)
    Pack {
        /// Archive to write
        #[arg(short, long)]
        output: PathBuf,
        /// Add to an existing archive instead of replacing it
        #[arg(short, long)]
        append: bool,
        /// zstd level (1-22)
        #[arg(short, long, default_value_t = Options::default().level)]
        level: i32,
        /// Target uncompressed size of each segment, in MiB. Bigger segments
        /// compress better; smaller ones let search skip more precisely.
        #[arg(long, default_value_t = Options::default().segment_bytes >> 20)]
        segment_mb: usize,
        /// Encoder threads
        #[arg(short = 'j', long, default_value_t = Options::default().threads)]
        threads: usize,
        /// Don't print the summary line
        #[arg(short, long)]
        quiet: bool,
        /// Stream name to use for stdin
        #[arg(long, default_value = "stdin")]
        name: String,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// Restore the original files into a directory
    Unpack {
        archive: PathBuf,
        /// Directory to write into
        #[arg(short = 'C', long, default_value = ".")]
        dir: PathBuf,
    },
    /// Decompress streams to stdout
    Cat {
        archive: PathBuf,
        /// Only these streams (default: all, in order)
        #[arg(short, long)]
        stream: Vec<String>,
    },
    /// List the streams in an archive
    Ls { archive: PathBuf },
    /// Search archives with a glob (`*` any run, `?` any byte) without
    /// decompressing them whole
    Grep {
        pattern: String,
        #[arg(required = true)]
        archives: Vec<PathBuf>,
        /// Case-insensitive (ASCII)
        #[arg(short = 'i', long)]
        ignore_case: bool,
        /// Print only the number of matching lines
        #[arg(short, long)]
        count: bool,
        /// Prefix lines with their line number in the stream
        #[arg(short = 'n', long)]
        line_number: bool,
        /// Always prefix lines with the stream name
        #[arg(short = 'H', long)]
        with_stream: bool,
        /// Only lines at or after this time (2015-10-18, 2015-10-18T18:01:47, epoch seconds)
        #[arg(long)]
        after: Option<String>,
        /// Only lines before this time
        #[arg(long)]
        before: Option<String>,
        /// Only search these streams
        #[arg(short, long)]
        stream: Vec<String>,
        /// Stop after this many matches
        #[arg(short = 'm', long)]
        max_count: Option<u64>,
        /// Report how much work was skipped, on stderr
        #[arg(long)]
        stats: bool,
    },
    /// Show where an archive's bytes go, block by block
    Stats { archive: PathBuf },
    /// Show the distinct line templates (log types), most common first
    Templates {
        archive: PathBuf,
        /// How many to show
        #[arg(long, default_value_t = 30)]
        top: usize,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) if is_broken_pipe(&*e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("logjar: {e}");
            ExitCode::from(2)
        }
    }
}

fn is_broken_pipe(e: &(dyn std::error::Error + 'static)) -> bool {
    let io = e
        .downcast_ref::<io::Error>()
        .or_else(|| match e.downcast_ref::<logjar::Error>() {
            Some(logjar::Error::Io(io)) => Some(io),
            _ => None,
        });
    io.is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe)
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn run(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Pack {
            output,
            append,
            level,
            segment_mb,
            threads,
            quiet,
            name,
            inputs,
        } => {
            let opts = Options {
                level,
                segment_bytes: segment_mb.max(1) << 20,
                threads,
                ..Options::default()
            };
            let mut w = if append {
                Writer::append(&output, opts)?
            } else {
                Writer::create(&output, opts)?
            };
            let (mut raw, mut lines) = (0u64, 0u64);
            for input in &inputs {
                let stats = if input.as_os_str() == "-" {
                    w.add_stream(&name, io::stdin().lock())?
                } else {
                    let f = File::open(input).map_err(|e| format!("{}: {e}", input.display()))?;
                    w.add_stream(&stream_name(input), BufReader::with_capacity(1 << 20, f))?
                };
                raw += stats.raw_bytes;
                lines += stats.lines;
            }
            w.finish()?;
            let size = std::fs::metadata(&output)?.len();
            if !quiet {
                eprintln!(
                    "{}: {lines} lines, {} -> {} ({:.1}x)",
                    output.display(),
                    human(raw),
                    human(size),
                    raw as f64 / size.max(1) as f64
                );
            }
        }
        Cmd::Unpack { archive, dir } => {
            let a = Archive::open(&archive)?;
            for (i, s) in a.index().streams.iter().enumerate() {
                let path = dir.join(safe_relative(&s.name)?);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut out = BufWriter::new(File::create(&path)?);
                a.write_stream(i as u32, &mut out)?;
                out.flush()?;
            }
        }
        Cmd::Cat { archive, stream } => {
            let a = Archive::open(&archive)?;
            let ids: Vec<u32> = if stream.is_empty() {
                (0..a.index().streams.len() as u32).collect()
            } else {
                stream
                    .iter()
                    .map(|n| {
                        a.stream_id(n)
                            .ok_or_else(|| format!("no stream named {n:?}"))
                    })
                    .collect::<Result<_, _>>()?
            };
            let mut out = BufWriter::with_capacity(1 << 16, io::stdout().lock());
            for id in ids {
                a.write_stream(id, &mut out)?;
            }
            out.flush()?;
        }
        Cmd::Ls { archive } => {
            let a = Archive::open(&archive)?;
            let idx = a.index();
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "{:>12} {:>10} {:>10} {:>7}  stream",
                "lines", "raw", "stored", "ratio"
            )?;
            for (i, s) in idx.streams.iter().enumerate() {
                let segs = idx.segments.iter().filter(|g| g.stream == i as u32);
                let (lines, raw, stored) = segs.fold((0, 0, 0), |(l, r, c), g| {
                    (l + g.lines, r + g.raw_bytes, c + g.len)
                });
                writeln!(
                    out,
                    "{lines:>12} {:>10} {:>10} {:>6.1}x  {}",
                    human(raw),
                    human(stored),
                    raw as f64 / stored.max(1) as f64,
                    s.name
                )?;
            }
        }
        Cmd::Grep {
            pattern,
            archives,
            ignore_case,
            count,
            line_number,
            with_stream,
            after,
            before,
            stream,
            max_count,
            stats,
        } => {
            let mut q = Query::new(&pattern)?.ignore_case(ignore_case);
            if let Some(t) = after {
                q = q.after(Query::parse_time(&t)?);
            }
            if let Some(t) = before {
                q = q.before(Query::parse_time(&t)?);
            }
            let mut out = BufWriter::with_capacity(1 << 16, io::stdout().lock());
            let mut total = 0u64;
            let mut io_err = None;
            for path in &archives {
                let a = Archive::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
                let ids: Vec<u32> = stream.iter().filter_map(|n| a.stream_id(n)).collect();
                if !stream.is_empty() && ids.is_empty() {
                    continue;
                }
                let searched = if ids.is_empty() {
                    a.index().streams.len()
                } else {
                    ids.len()
                };
                let prefix = with_stream || archives.len() > 1 || searched > 1;
                let names = &a.index().streams;
                let started = std::time::Instant::now();
                let st = a.search(&q, &ids, |m| {
                    total += 1;
                    if !count {
                        let r = (|| {
                            if prefix {
                                write!(out, "{}:", names[m.stream as usize].name)?;
                            }
                            if line_number {
                                write!(out, "{}:", m.line_number)?;
                            }
                            out.write_all(&m.line)?;
                            out.write_all(b"\n")
                        })();
                        if let Err(e) = r {
                            io_err = Some(e);
                            return false;
                        }
                    }
                    max_count.map_or(true, |mx| total < mx)
                })?;
                if let Some(e) = io_err.take() {
                    return Err(e.into());
                }
                if stats {
                    eprintln!(
                        "{}: {} matches in {:.3}s | segments {} (skipped {} by index, {} by templates) | templates {}/{} | lines decoded {}/{}",
                        path.display(),
                        st.matches,
                        started.elapsed().as_secs_f64(),
                        st.segments,
                        st.segments_skipped_index,
                        st.segments_skipped_templates,
                        st.templates_matched,
                        st.templates,
                        st.lines_decoded,
                        st.lines_total
                    );
                }
                if max_count.is_some_and(|mx| total >= mx) {
                    break;
                }
            }
            if count {
                writeln!(out, "{total}")?;
            }
            out.flush()?;
            return Ok(if total > 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            });
        }
        Cmd::Stats { archive } => {
            let a = Archive::open(&archive)?;
            let st = a.stats()?;
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "{} lines in {} segments: {} -> {} ({:.1}x)",
                st.lines,
                st.segments,
                human(st.raw_bytes),
                human(a.size()),
                st.raw_bytes as f64 / a.size().max(1) as f64
            )?;
            writeln!(
                out,
                "{} template entries, {} dictionary entries",
                st.templates, st.dict_entries
            )?;
            writeln!(
                out,
                "{:<8} {:>12} {:>12} {:>7} {:>7}",
                "block", "raw", "stored", "ratio", "share"
            )?;
            for (name, raw, comp) in st.blocks {
                writeln!(
                    out,
                    "{name:<8} {:>12} {:>12} {:>6.1}x {:>6.1}%",
                    human(raw),
                    human(comp),
                    raw as f64 / comp.max(1) as f64,
                    100.0 * comp as f64 / st.stored_bytes.max(1) as f64
                )?;
            }
        }
        Cmd::Templates { archive, top } => {
            let a = Archive::open(&archive)?;
            let all = a.templates()?;
            let lines: u64 = all.iter().map(|t| t.1).sum();
            let mut out = io::stdout().lock();
            writeln!(out, "{} templates over {lines} lines", all.len())?;
            for (t, n) in all.iter().take(top) {
                writeln!(
                    out,
                    "{n:>10} {:>6.2}%  {t}",
                    100.0 * *n as f64 / lines.max(1) as f64
                )?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Stream names use forward slashes so archives made on Windows unpack the
/// same way everywhere.
fn stream_name(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Stream names come from the archive, which may be untrusted: refuse
/// anything that would write outside the target directory.
fn safe_relative(name: &str) -> Res<PathBuf> {
    let p = Path::new(name);
    let ok = !name.is_empty()
        && p.components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !ok {
        return Err(format!("refusing to unpack stream with unsafe name {name:?}").into());
    }
    Ok(p.to_path_buf())
}

fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
