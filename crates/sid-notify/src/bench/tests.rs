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

#[test]
fn rss_is_read_in_bytes_and_zero_without_it() {
    let status = "Name:\tpostgres\nVmHWM:\t  9000 kB\nVmRSS:\t  4096 kB\nThreads:\t1\n";
    assert_eq!(parse_rss(status), 4096 * 1024);
    // A kernel thread has no VmRSS line.
    assert_eq!(parse_rss("Name:\tkworker/0:1\nThreads:\t1\n"), 0);
}
