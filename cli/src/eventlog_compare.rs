/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! `--compare-eventlog`: align the computed RTMR events with the events in a
//! TDX CCEL event log and explain the mismatches.
use anyhow::{Context, Result};
use fs_err as fs;
use sha2::{Digest, Sha384};
use std::path::Path;
use tdx_measure::eventlog::{self, Event, EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_GPT_EVENT, LINUX_INITRD_TAG};
use tdx_measure::{describe_gpt_event_data, Machine};

pub const DEFAULT_CCEL: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// Longest-common-subsequence alignment of two digest lists.
fn align(a: &[&[u8]], b: &[&[u8]]) -> Vec<(Option<usize>, Option<usize>)> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] { lcs[i + 1][j + 1] + 1 } else { lcs[i + 1][j].max(lcs[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            out.push((Some(i), Some(j)));
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push((None, Some(j)));
            j += 1;
        } else {
            out.push((Some(i), None));
            i += 1;
        }
    }
    out
}

fn short(d: &[u8]) -> String {
    hex::encode(&d[..d.len().min(8)])
}

pub fn compare_eventlog(machine: &Machine, ccel: &Path) -> Result<()> {
    let raw = fs::read(ccel).context("Failed to read the event log")?;
    let events = eventlog::parse_ccel(&raw).context("Failed to parse the event log")?;
    let tool_logs = machine.rtmr_event_logs().context("Failed to compute the RTMR events")?;

    println!("\n=== Event log comparison ({}) ===", ccel.display());
    println!("Legend: '=' matches, '-' only in the event log, '+' only computed by tdx-measure");

    let mut unmatched: Vec<&Event> = Vec::new();
    for (rtmr, tool) in tool_logs.iter().enumerate() {
        let log: Vec<&Event> = events.iter().filter(|e| e.rtmr() == Some(rtmr)).collect();
        let log_digests: Vec<&[u8]> = log.iter().map(|e| e.sha384.as_deref().unwrap_or(&[])).collect();
        let tool_digests: Vec<&[u8]> = tool.iter().map(|d| d.as_slice()).collect();
        let replay = eventlog::replay(&log_digests.iter().map(|d| d.to_vec()).collect::<Vec<_>>());
        let computed = eventlog::replay(tool);
        println!(
            "\nRTMR{rtmr}: {} (event log replay {}, computed {})",
            if replay == computed { "MATCH" } else { "MISMATCH" },
            hex::encode(&replay),
            hex::encode(&computed),
        );
        for (l, t) in align(&log_digests, &tool_digests) {
            match (l, t) {
                (Some(l), Some(_)) => {
                    let e = log[l];
                    println!("  =  #{:<3} [{:#010x}] {}  {}", e.index, e.offset, short(log_digests[l]), e.describe());
                }
                (Some(l), None) => {
                    let e = log[l];
                    println!("  -  #{:<3} [{:#010x}] {}  {}", e.index, e.offset, short(log_digests[l]), e.describe());
                    unmatched.push(e);
                }
                (None, Some(t)) => println!("  +  computed[{t}]       {}", short(tool_digests[t])),
                (None, None) => unreachable!(),
            }
        }
    }

    let fallback_in_log = events.iter().any(|e| {
        e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION && e.describe().to_ascii_lowercase().contains("fbx64")
    });
    match machine.shim_fallback() {
        Ok(computed) if computed != fallback_in_log => println!(
            "\nNOTE: event log shows a {} boot, but tdx-measure assumed shim_fallback={computed}",
            if fallback_in_log { "shim fallback (fbx64.efi)" } else { "non-fallback" },
        ),
        Ok(_) => {}
        Err(e) => println!("\nNOTE: failed to determine shim_fallback: {e:#}"),
    }

    for e in unmatched {
        if e.event_type == EV_EFI_GPT_EVENT {
            explain_gpt(machine, e);
        } else if e.tag_id() == Some(LINUX_INITRD_TAG) {
            explain_initrd(machine, e);
        }
    }
    Ok(())
}

fn explain_gpt(machine: &Machine, e: &Event) {
    println!("\n--- GPT mismatch (event #{}) ---", e.index);
    println!("The firmware measured the GPT below at boot; tdx-measure read the current disk.");
    let disk = match machine.gpt_event_data() {
        Ok(d) => d,
        Err(err) => {
            println!("Failed to read the GPT from the disk: {err:#}");
            return;
        }
    };
    let log_desc = describe_gpt_event_data(&e.data);
    let disk_desc = describe_gpt_event_data(&disk);
    println!("Differing fields (event log -> disk):");
    let fields = |s: &str| s.lines().skip(1).take_while(|l| !l.starts_with("  0")).map(String::from).collect::<Vec<_>>();
    let (lf, df) = (fields(&log_desc), fields(&disk_desc));
    for i in 0..lf.len().max(df.len()) {
        let (l, d) = (lf.get(i).map_or("", |s| s.trim()), df.get(i).map_or("", |s| s.trim()));
        if l != d {
            println!("  - {l}\n  + {d}");
        }
    }
    println!("\nEvent log GPT:\n{log_desc}\nDisk GPT:\n{disk_desc}");
}

fn explain_initrd(machine: &Machine, e: &Event) {
    println!("\n--- initrd mismatch (event #{}) ---", e.index);
    let expected = e.sha384.as_deref().map(hex::encode).unwrap_or_default();
    println!("Event log initrd SHA384: {expected}");
    let path = match machine.initrd_path() {
        Ok(Some(p)) => p,
        Ok(None) => {
            println!("initrd is not a local file (qcow2 source); cannot inspect it further");
            return;
        }
        Err(err) => {
            println!("Failed to locate the initrd: {err:#}");
            return;
        }
    };
    let boot_time = fs::read_to_string("/proc/stat").ok().and_then(|s| {
        s.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<i64>().ok()))
    });
    let mtime = |p: &Path| {
        p.metadata().ok()?.modified().ok()?
            .duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
    };
    match fs::read(&path) {
        Ok(data) => println!("{}: SHA384 {}", path.display(), hex::encode(Sha384::digest(&data))),
        Err(err) => println!("{err:#}"),
    }
    if let (Some(boot), Some(m)) = (boot_time, mtime(&path)) {
        if m > boot {
            println!("{} was modified {}s AFTER this boot started: it was regenerated (e.g. update-initramfs) \
                      after the firmware measured it; reboot and measure again", path.display(), m - boot);
        } else {
            println!("{} was last modified {}s before this boot", path.display(), boot - m);
        }
    }
    // Look for another initrd that matches the measured one.
    let dir = path.parent().unwrap_or(Path::new("/boot"));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let is_initrd = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("initrd"));
            if !is_initrd || p == path || !p.is_file() {
                continue;
            }
            if let Ok(data) = fs::read(&p) {
                if hex::encode(Sha384::digest(&data)) == expected {
                    println!("The measured initrd matches {}", p.display());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_reports_missing_and_extra_events() {
        let a: Vec<&[u8]> = vec![b"a", b"b", b"x", b"c"];
        let b: Vec<&[u8]> = vec![b"a", b"y", b"c"];
        assert_eq!(
            align(&a, &b),
            vec![(Some(0), Some(0)), (None, Some(1)), (Some(1), None), (Some(2), None), (Some(3), Some(2))]
        );
    }
}
