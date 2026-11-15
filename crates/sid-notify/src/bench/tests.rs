use std::time::Duration;

use super::*;

fn ms(samples: impl IntoIterator<Item = u64>) -> Vec<Duration> {
    samples.into_iter().map(Duration::from_millis).collect()
}

// A P999 from 500 samples is their maximum, not a quantile: it is not
// printed until ten samples lie above it.
#[test]
fn a_tail_quantile_needs_ten_samples_above_it() {
    let few = ms(1..=500);
    assert_eq!(quantile(&few, 999), None);
    assert_eq!(quantile(&few, 990), None);
    assert_eq!(quantile(&few, 500), Some(Duration::from_millis(251)));

    let enough = ms(1..=10_000);
    assert_eq!(quantile(&enough, 999), Some(Duration::from_millis(9_991)));
    assert_eq!(quantile(&enough, 990), Some(Duration::from_millis(9_901)));
}

// The process name sits in parentheses and may hold spaces and
// parentheses; utime and stime are read after its last `)`.
#[test]
fn stat_reads_name_and_cpu_after_the_last_parenthesis() {
    // Fields 3..15: state ppid pgrp session tty tpgid flags minflt cminflt
    // majflt cmajflt utime stime.
    let stat = "4242 (nats (main) x) S 1 4242 4242 0 -1 4194560 10 0 0 0 250 50 0 0 20 0";
    let (name, cpu) = parse_stat(stat).unwrap();
    assert_eq!(name, "nats (main) x");
    // 300 ticks at 100 per second.
    assert_eq!(cpu, Duration::from_secs(3));
}

// A truncated line is no measurement, not a zero.
#[test]
fn a_truncated_stat_line_is_refused() {
    assert_eq!(parse_stat("4242 (postgres) S 1 2 3"), None);
    assert_eq!(parse_stat("no name here"), None);
}

// A repeated delivery and a lost one in the same run are both reported: an
// aggregate send count would show them cancelling out as zero excess. A send
// to no owed delivery is reported apart from both.
#[test]
fn a_repeat_and_a_loss_do_not_cancel_out() {
    let ledger = Ledger::default();
    let owed = vec!["e1".to_owned(), "e2".to_owned()];
    // e1: both channels, its email twice. e2: email only. e3: never owed.
    ledger.record("e1", "email");
    ledger.record("e1", "email");
    ledger.record("e1", "webhook");
    ledger.record("e2", "email");
    ledger.record("e3", "webhook");
    assert_eq!(
        ledger.tally(&owed),
        Tally {
            missing: 1,
            repeated: 1,
            unexpected: 1,
        }
    );
    // Four sends for four owed deliveries plus one stray: a count would say
    // one excess and hide the loss.
}

// Every owed delivery made once is a clean tally.
#[test]
fn each_delivery_once_tallies_clean() {
    let ledger = Ledger::default();
    let owed = vec!["e1".to_owned()];
    for channel in CHANNELS {
        ledger.record("e1", channel);
    }
    assert_eq!(ledger.tally(&owed), Tally::default());
}

// The run's script names its servers' cgroups; a malformed pair is
// ignored rather than read as some other server's path.
#[test]
fn owned_cgroups_are_named_pairs() {
    let parsed = parse_cgroups(
        " postgres=/sys/fs/cgroup/system.slice/docker-a.scope , broken, nats=/sys/fs/cgroup/b ",
    );
    assert_eq!(
        parsed,
        vec![
            (
                "postgres".to_owned(),
                std::path::PathBuf::from("/sys/fs/cgroup/system.slice/docker-a.scope")
            ),
            (
                "nats".to_owned(),
                std::path::PathBuf::from("/sys/fs/cgroup/b")
            ),
        ]
    );
    assert!(parse_cgroups("").is_empty());
}

// cgroup v2 `cpu.stat` counts microseconds; a file without `usage_usec` is
// no measurement, not a zero.
#[test]
fn cgroup_cpu_is_read_in_microseconds() {
    let stat = "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n";
    assert_eq!(parse_cpu_stat(stat), Some(Duration::from_millis(2_500)));
    assert_eq!(parse_cpu_stat("user_usec 1\n"), None);
}

#[test]
fn rss_is_read_in_bytes_and_zero_without_it() {
    let status = "Name:\tpostgres\nVmHWM:\t  9000 kB\nVmRSS:\t  4096 kB\nThreads:\t1\n";
    assert_eq!(parse_rss(status), 4096 * 1024);
    // A kernel thread has no VmRSS line.
    assert_eq!(parse_rss("Name:\tkworker/0:1\nThreads:\t1\n"), 0);
}

// Regression: a replica that exited before reporting ready (or before the
// backlog drained) left the run waiting forever. A replica ending fails a
// wait that cannot complete, naming the replica.
#[tokio::test]
#[should_panic(expected = "replica 2: its output ended")]
async fn a_replica_ending_fails_a_pending_wait() {
    let (failed, mut ended) = tokio::sync::mpsc::unbounded_channel();
    failed
        .send("replica 2: its output ended".to_string())
        .unwrap();
    unless_ended(std::future::pending::<()>(), &mut ended).await;
}

// Progress that arrives is passed through while every replica keeps running.
#[tokio::test]
async fn a_wait_completes_while_replicas_run() {
    let (_running, mut ended) = tokio::sync::mpsc::unbounded_channel::<String>();
    assert_eq!(unless_ended(async { 7 }, &mut ended).await, 7);
}
