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
use tdx_measure::eventlog::{
    self, Event, EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_GPT_EVENT, LINUX_INITRD_TAG, LINUX_LOAD_OPTIONS_TAG,
};
use tdx_measure::{describe_gpt_event_data, uki, Machine, TdxMeasurements};

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

/// Returns whether everything that could be checked matches.
pub fn compare_eventlog(machine: &Machine, measurements: &TdxMeasurements, ccel: &Path) -> Result<bool> {
    let raw = fs::read(ccel).context("Failed to read the event log")?;
    let events = eventlog::parse_ccel(&raw).context("Failed to parse the event log")?;
    let tool_logs = machine.rtmr_event_logs().context("Failed to compute the RTMR events")?;

    println!("\n=== Event log comparison ({}) ===", ccel.display());
    println!("Legend: '=' matches, '-' only in the event log, '+' only computed by tdx-measure");

    let mut unmatched: Vec<&Event> = Vec::new();
    let mut computed_only: Vec<(usize, usize, &[u8])> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut replays = Vec::new();
    for (rtmr, tool) in tool_logs.iter().enumerate() {
        let log: Vec<&Event> = events.iter().filter(|e| e.rtmr() == Some(rtmr)).collect();
        let log_digests: Vec<&[u8]> = log.iter().map(|e| e.sha384.as_deref().unwrap_or(&[])).collect();
        let tool_digests: Vec<&[u8]> = tool.iter().map(|d| d.as_slice()).collect();
        let replay = eventlog::replay(&log_digests.iter().map(|d| d.to_vec()).collect::<Vec<_>>());
        let computed = eventlog::replay(tool);
        replays.push(replay.clone());
        if replay != computed {
            failures.push(format!("RTMR{rtmr} differs from the event log (see \"Mismatch details\")"));
        }
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
                (None, Some(t)) => {
                    println!("  +  computed[{t}]       {}", short(tool_digests[t]));
                    computed_only.push((rtmr, t, tool_digests[t]));
                }
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

    if !unmatched.is_empty() || !computed_only.is_empty() {
        println!("\n=== Mismatch details ===");
    }
    let uki_boot = machine.is_uki_boot();
    let mut uki_explained = false;
    for e in &unmatched {
        dump_event(e);
        if e.event_type == EV_EFI_GPT_EVENT {
            explain_gpt(machine, e);
        } else if uki_boot && e.tag_id() == Some(LINUX_LOAD_OPTIONS_TAG) {
            explain_uki_cmdline(machine, e);
        } else if uki_boot && (e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION
            || e.tag_id() == Some(LINUX_INITRD_TAG) && !matches!(machine.initrd_path(), Ok(Some(_))))
        {
            explain_uki(machine, e, !std::mem::replace(&mut uki_explained, true));
        } else if e.tag_id() == Some(LINUX_INITRD_TAG) {
            explain_initrd(machine, e);
        }
    }
    for (rtmr, t, digest) in &computed_only {
        println!("\n---- computed RTMR{rtmr} event [{t}] (not in the event log) ----");
        println!("Digest : {}", hex::encode(digest));
    }

    // The event log only covers RTMRs; the registers of the running TD also
    // give MRTD and catch extensions that are missing from the log.
    let mut td_checked = false;
    if Path::new(TDX_GUEST_DEVICE).exists() {
        let own_log = ccel == Path::new(DEFAULT_CCEL);
        match read_tdreport() {
            Ok(report) => {
                failures.extend(compare_td_registers(measurements, &report, own_log.then_some(&replays[..])));
                td_checked = true;
            }
            Err(e) => println!("\nNOTE: failed to read the TDREPORT from {TDX_GUEST_DEVICE}: {e:#}"),
        }
    }

    println!("\n=== RESULT ===");
    if failures.is_empty() {
        if td_checked {
            println!("SUCCESS: MRTD, RTMR0, RTMR1 and RTMR2 computed by tdx-measure match the running TD and its event log");
        } else {
            println!("SUCCESS: RTMR0, RTMR1 and RTMR2 computed by tdx-measure match the event log");
            println!("(MRTD is not in the event log; run inside the TD with {TDX_GUEST_DEVICE} to check it)");
        }
    } else {
        println!("FAILURE: {} mismatch(es):", failures.len());
        for f in &failures {
            println!("  - {f}");
        }
    }
    Ok(failures.is_empty())
}

/// Hex dump in the style of common TDX event log dumpers.
fn hex_dump(base: usize, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let ascii: String = chunk.iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!("{:08X}  {:<47}  {}", base + i * 16, hex.join(" "), ascii);
    }
}

fn dump_event(e: &Event) {
    println!("\n---- event log entry #{} [{:#010x}] (not computed by tdx-measure) ----", e.index, e.offset);
    if let Some(rtmr) = e.rtmr() {
        println!("RTMR   : {rtmr}");
    }
    println!("Type   : {:#x} ({})", e.event_type, eventlog::event_type_name(e.event_type));
    println!("Digest : {}", e.sha384.as_deref().map(hex::encode).unwrap_or_default());
    println!("Event  : {}", e.describe());
    println!("RAW DATA ({} bytes):", e.raw.len());
    hex_dump(e.offset, &e.raw);
}

const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";
/// `_IOWR('T', 1, struct tdx_report_req)` from linux/tdx-guest.h.
// The request type is c_ulong on glibc and c_int on musl.
const TDX_CMD_GET_REPORT0: libc::Ioctl = 0xC440_5401_u32 as libc::Ioctl;
const TDX_REPORTDATA_LEN: usize = 64;
const TDX_REPORT_LEN: usize = 1024;
/// TDINFO starts at 512 in the TDREPORT: ATTRIBUTES(8), XFAM(8), MRTD(48),
/// MRCONFIGID, MROWNER, MROWNERCONFIG (48 each), then RTMR0..3 (48 each).
const TDREPORT_MRTD: usize = 512 + 16;
const TDREPORT_RTMR0: usize = TDREPORT_MRTD + 4 * 48;

fn read_tdreport() -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let dev = fs::OpenOptions::new().read(true).write(true).open(TDX_GUEST_DEVICE)?;
    let mut req = [0u8; TDX_REPORTDATA_LEN + TDX_REPORT_LEN];
    // SAFETY: `req` has the size and layout of `struct tdx_report_req`.
    let rc = unsafe { libc::ioctl(dev.as_raw_fd(), TDX_CMD_GET_REPORT0, req.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("TDX_CMD_GET_REPORT0 failed");
    }
    Ok(req[TDX_REPORTDATA_LEN..].to_vec())
}

fn td_register(report: &[u8], offset: usize) -> &[u8] {
    &report[offset..offset + 48]
}

/// Compare the computed measurements (and, for the TD's own event log, the
/// log replay) with the registers in the running TD's TDREPORT.
fn compare_td_registers(m: &TdxMeasurements, report: &[u8], replays: Option<&[Vec<u8>]>) -> Vec<String> {
    println!("\n=== Running TD registers (TDREPORT from {TDX_GUEST_DEVICE}) ===");
    let mut failures = Vec::new();
    let verdict = |ok: bool| if ok { "MATCH" } else { "MISMATCH" };
    let mrtd = td_register(report, TDREPORT_MRTD);
    println!("MRTD : {} (TD {}, computed {})", verdict(mrtd == m.mrtd), hex::encode(mrtd), hex::encode(&m.mrtd));
    if mrtd != m.mrtd.as_slice() {
        println!("  -> qemu_options.bios is not the firmware this TD was launched with");
        failures.push("MRTD differs from the TD: qemu_options.bios is not the firmware this TD was launched with".to_string());
    }
    for (i, computed) in [&m.rtmr0, &m.rtmr1, &m.rtmr2].into_iter().enumerate() {
        let td = td_register(report, TDREPORT_RTMR0 + i * 48);
        println!("RTMR{i}: {} (TD {}, computed {})", verdict(td == computed.as_slice()), hex::encode(td), hex::encode(computed));
        if td != computed.as_slice() {
            failures.push(format!("RTMR{i} differs from the TD register"));
        }
        if let Some(replay) = replays.map(|r| r[i].as_slice()) {
            if replay != td {
                println!(
                    "  -> the event log replay ({}) differs from the TD register: RTMR{i} was \
                     extended by events missing from the log (e.g. at runtime)",
                    hex::encode(replay)
                );
            } else if td != computed.as_slice() {
                println!("  -> see the RTMR{i} event comparison above");
            }
        }
    }
    println!("RTMR3: TD {} (not computed by tdx-measure)", hex::encode(td_register(report, TDREPORT_RTMR0 + 3 * 48)));
    failures
}

/// Report whether `path` changed after this boot, when it was measured.
fn print_mtime(path: &Path, regenerated_by: &str) {
    let boot_time = fs::read_to_string("/proc/stat").ok().and_then(|s| {
        s.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<i64>().ok()))
    });
    let mtime = path.metadata().ok().and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    if let (Some(boot), Some(m)) = (boot_time, mtime) {
        if m > boot {
            println!("{} was modified {}s AFTER this boot started: it was regenerated (e.g. {regenerated_by}) \
                      after it was measured at boot; reboot and measure again", path.display(), m - boot);
        } else {
            println!("{} was last modified {}s before this boot", path.display(), boot - m);
        }
    }
}

/// A UKI, its kernel or its initrd differs: check whether the UKI changed.
fn explain_uki(machine: &Machine, e: &Event, inspect_file: bool) {
    println!("\n--- UKI mismatch (event #{}) ---", e.index);
    if e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION && e.data.len() >= 16 {
        let len = u64::from_le_bytes(e.data[8..16].try_into().unwrap());
        println!("Firmware loaded a {len:#x} ({len}) byte image");
    }
    if !inspect_file {
        return;
    }
    let guest = machine.uki_guest_path();
    match machine.uki_path() {
        Ok(Some(path)) => match path.metadata() {
            Ok(m) => {
                println!("{}: {:#x} ({}) bytes; tdx-measure measured this UKI", path.display(), m.len(), m.len());
                print_mtime(&path, "ukify or kernel-install");
            }
            Err(err) => println!("Failed to read {}: {err}", path.display()),
        },
        Ok(None) => println!("{guest} is in the qcow2 image; cannot inspect it further"),
        Err(err) => println!("Failed to locate {guest}: {err:#}"),
    }
    println!("If firmware booted another UKI (see the device path above), set measure_config.uki to it");
}

/// The kernel command line differs: show which candidate the event log measured.
fn explain_uki_cmdline(machine: &Machine, e: &Event) {
    println!("\n--- kernel command line mismatch (event #{}) ---", e.index);
    let expected = e.sha384.as_deref().map(hex::encode).unwrap_or_default();
    println!("Event log LoadOptions SHA384: {expected}");
    let source = if machine.measure_config.as_ref().is_some_and(|mc| mc.cmdline.is_some()) {
        "measure_config.cmdline"
    } else {
        "UKI .cmdline"
    };
    let mut candidates = Vec::new();
    let mut major = None;
    match machine.uki_boot() {
        Ok(uki) => {
            println!("systemd-stub version (.sdmagic): {}", uki.stub_version.as_deref().unwrap_or("unknown"));
            major = uki.stub_version.as_deref().and_then(uki::stub_major);
            match uki.cmdline {
                Some(c) => candidates.push((source, c)),
                None => println!("The UKI has no .cmdline section"),
            }
        }
        Err(err) => println!("Failed to read the UKI command line: {err:#}"),
    }
    if let Ok(c) = fs::read_to_string("/proc/cmdline") {
        candidates.push(("/proc/cmdline", uki::stub_cmdline(c.as_bytes(), major)));
    }
    for (source, cmdline) in &candidates {
        println!("{source}: {cmdline:?}");
        let with_nul = uki::load_options(cmdline);
        for (variant, data) in [("with NUL", &with_nul[..]), ("without NUL", &with_nul[..with_nul.len() - 2])] {
            let digest = hex::encode(Sha384::digest(data));
            let verdict = if digest == expected { "  <-- MATCHES the event log" } else { "" };
            println!("  UTF-16 {variant}: {digest}{verdict}");
        }
    }
    println!("Set measure_config.cmdline to the matching command line to override the UKI's .cmdline");
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
    match fs::read(&path) {
        Ok(data) => println!("{}: SHA384 {}", path.display(), hex::encode(Sha384::digest(&data))),
        Err(err) => println!("{err:#}"),
    }
    print_mtime(&path, "update-initramfs");
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
