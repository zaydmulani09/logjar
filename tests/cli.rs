//! End-to-end tests that drive the real `logjar` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_logjar"))
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("logjar-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str], cwd: &Path) -> Output {
    bin().args(args).current_dir(cwd).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

const APP: &str = "\
2015-10-18 18:01:47,978 INFO [main] Created MRAppMaster for application appattempt_1445144423722_0020_000001
2015-10-18 18:01:48,963 INFO [main] Executing with tokens:
2015-10-18 18:05:12,100 ERROR [RMCommunicator] Failed to contact 10.86.169.121:8030 after 3 retries
2015-10-18 18:09:30,001 WARN [main] Slow GC pause 412.7 ms
\tat org.apache.hadoop.ipc.Client.call(Client.java:1475)
2015-10-18 18:12:00,555 error [main] lowercase error 7
";

const SYS: &str =
    "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; rhost=218.188.2.4\r
Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown\r
";

fn setup(name: &str) -> PathBuf {
    let d = dir(name);
    std::fs::write(d.join("app.log"), APP).unwrap();
    std::fs::create_dir_all(d.join("sys")).unwrap();
    std::fs::write(d.join("sys/auth.log"), SYS).unwrap();
    let o = run(
        &["pack", "-q", "-o", "a.ljar", "app.log", "sys/auth.log"],
        &d,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    d
}

#[test]
fn pack_cat_unpack_roundtrip() {
    let d = setup("roundtrip");
    let cat = run(&["cat", "a.ljar"], &d);
    assert_eq!(stdout(&cat), format!("{APP}{SYS}"));
    let one = run(&["cat", "a.ljar", "-s", "sys/auth.log"], &d);
    assert_eq!(stdout(&one), SYS);

    assert!(run(&["unpack", "a.ljar", "-C", "out"], &d).status.success());
    assert_eq!(std::fs::read_to_string(d.join("out/app.log")).unwrap(), APP);
    assert_eq!(
        std::fs::read_to_string(d.join("out/sys/auth.log")).unwrap(),
        SYS
    );

    let ls = stdout(&run(&["ls", "a.ljar"], &d));
    assert!(
        ls.contains("app.log") && ls.contains("sys/auth.log"),
        "{ls}"
    );
}

#[test]
fn grep_follows_grep_conventions() {
    let d = setup("grep");
    let o = run(&["grep", "ERROR", "a.ljar"], &d);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        stdout(&o),
        "app.log:2015-10-18 18:05:12,100 ERROR [RMCommunicator] Failed to contact 10.86.169.121:8030 after 3 retries\n"
    );

    let o = run(&["grep", "no such text", "a.ljar"], &d);
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stdout.is_empty());

    assert_eq!(
        stdout(&run(&["grep", "-c", "-i", "error", "a.ljar"], &d)),
        "2\n"
    );
    assert_eq!(
        stdout(&run(&["grep", "-c", "pam_unix*rhost=218", "a.ljar"], &d)),
        "1\n"
    );

    let o = stdout(&run(
        &["grep", "-n", "-s", "app.log", "Client.java", "a.ljar"],
        &d,
    ));
    assert_eq!(
        o,
        "5:\tat org.apache.hadoop.ipc.Client.call(Client.java:1475)\n"
    );

    let o = stdout(&run(
        &[
            "grep",
            "--after",
            "2015-10-18T18:05",
            "--before",
            "2015-10-18T18:10",
            "main",
            "a.ljar",
        ],
        &d,
    ));
    assert_eq!(
        o,
        "app.log:2015-10-18 18:09:30,001 WARN [main] Slow GC pause 412.7 ms\n"
    );

    assert_eq!(
        stdout(&run(&["grep", "-m", "1", "-c", "main", "a.ljar"], &d)),
        "1\n"
    );
}

#[test]
fn append_continues_streams() {
    let d = setup("append");
    std::fs::write(
        d.join("more.log"),
        "2015-10-18 18:20:00,000 INFO [main] done\n",
    )
    .unwrap();
    let o = run(&["pack", "-q", "--append", "-o", "a.ljar", "more.log"], &d);
    assert!(o.status.success());
    assert_eq!(stdout(&run(&["grep", "-c", "done", "a.ljar"], &d)), "1\n");
    assert_eq!(
        stdout(&run(&["cat", "a.ljar"], &d)),
        format!("{APP}{SYS}2015-10-18 18:20:00,000 INFO [main] done\n")
    );
}

#[test]
fn templates_and_stats() {
    let d = setup("templates");
    let t = stdout(&run(&["templates", "a.ljar"], &d));
    assert!(t.contains("combo sshd(pam_unix)[<int>]"), "{t}");
    let s = stdout(&run(&["stats", "a.ljar"], &d));
    assert!(s.contains("8 lines in 2 segments"), "{s}");
}

#[test]
fn unpack_refuses_path_traversal() {
    let d = dir("traversal");
    let mut w = logjar::Writer::create(d.join("evil.ljar"), logjar::Options::default()).unwrap();
    w.add_stream("../escaped.log", &b"x 1\n"[..]).unwrap();
    w.finish().unwrap();
    let o = run(&["unpack", "evil.ljar", "-C", "out"], &d);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("unsafe name"));
    assert!(!d.join("escaped.log").exists());
}

#[test]
fn corrupt_input_is_a_clean_error() {
    let d = dir("corrupt");
    std::fs::write(
        d.join("bad.ljar"),
        b"LOGJAR\0\x01 definitely not an archive",
    )
    .unwrap();
    let o = run(&["grep", "x", "bad.ljar"], &d);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("corrupt"));
}

#[test]
fn ingest_then_compact() {
    use std::io::Write;
    use std::process::Stdio;
    let d = dir("ingest");
    for round in 0..2 {
        let mut child = bin()
            .args(["ingest", "-o", "live.ljar", "--name", "svc"])
            .current_dir(&d)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for i in 0..100 {
            writeln!(
                stdin,
                "2024-05-01 12:00:{:02} INFO round {round} request {i} ok",
                i % 60
            )
            .unwrap();
        }
        drop(stdin);
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(
        stdout(&run(&["grep", "-c", "request 7 ok", "live.ljar"], &d)),
        "2\n"
    );
    let before = stdout(&run(&["cat", "live.ljar"], &d));
    assert_eq!(before.lines().count(), 200);
    assert!(run(&["compact", "live.ljar"], &d).status.success());
    assert_eq!(stdout(&run(&["cat", "live.ljar"], &d)), before);
    assert!(stdout(&run(&["stats", "live.ljar"], &d)).contains("in 1 segments"));
}

#[test]
fn grep_alternatives_inversion_and_json() {
    let d = setup("grep2");
    let o = stdout(&run(
        &["grep", "-c", "-e", "ERROR", "-e", "WARN", "a.ljar"],
        &d,
    ));
    assert_eq!(o, "2\n");
    // 8 lines total, 6 contain "2015" or "Jun"-prefixed sshd lines contain "combo".
    let o = stdout(&run(
        &["grep", "-c", "-v", "-e", "2015", "-e", "combo", "a.ljar"],
        &d,
    ));
    assert_eq!(o, "1\n"); // the stack-trace line
    let o = stdout(&run(&["grep", "--json", "Slow GC", "a.ljar"], &d));
    assert_eq!(
        o,
        "{\"stream\":\"app.log\",\"line\":4,\"time_ns\":1445191770001000000,\"text\":\"2015-10-18 18:09:30,001 WARN [main] Slow GC pause 412.7 ms\"}\n"
    );
    let o = stdout(&run(&["grep", "--json", "Client.java", "a.ljar"], &d));
    assert!(
        o.contains("\"time_ns\":null") && o.contains("\"text\":\"\\tat org"),
        "{o}"
    );
}

#[test]
fn cat_time_slice() {
    let d = setup("slice");
    let o = stdout(&run(
        &[
            "cat",
            "a.ljar",
            "--after",
            "2015-10-18 18:05",
            "--before",
            "2015-10-18 18:12",
        ],
        &d,
    ));
    assert_eq!(
        o,
        "2015-10-18 18:05:12,100 ERROR [RMCommunicator] Failed to contact 10.86.169.121:8030 after 3 retries\n\
         2015-10-18 18:09:30,001 WARN [main] Slow GC pause 412.7 ms\n"
    );
}

#[test]
fn pack_reads_gzip_input() {
    use std::io::Write;
    let d = dir("gzip");
    let f = std::fs::File::create(d.join("old.log.gz")).unwrap();
    let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    gz.write_all(APP.as_bytes()).unwrap();
    gz.finish().unwrap();
    assert!(run(&["pack", "-q", "-o", "g.ljar", "old.log.gz"], &d)
        .status
        .success());
    assert!(stdout(&run(&["ls", "g.ljar"], &d)).contains(" old.log\n"));
    assert_eq!(stdout(&run(&["cat", "g.ljar"], &d)), APP);
}
