/*
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

//! Generate a `metadata.json` (Machine) from a raw QEMU command line.

use anyhow::{bail, Context, Result};
use fs_err as fs;
use qcparser::{Grouped, Props};
use std::path::{Path, PathBuf};
use tdx_measure::{Machine, MeasureConfig, QemuOptions};

const BIOS_PLACEHOLDER: &str = "[Path to OVMF.fd]";

/// Render a grouped property map back into a QEMU comma-separated option value,
/// placing the positional value (driver/type/model/...) first.
fn render_props(props: &Props, positional_key: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(pos) = props.get(positional_key) {
        parts.push(pos.clone());
    }
    for (k, v) in props {
        if k == positional_key {
            continue;
        }
        parts.push(format!("{k}={v}"));
    }
    parts.join(",")
}

fn render_all(items: &[Props], positional_key: &str) -> Vec<String> {
    items.iter().map(|p| render_props(p, positional_key)).collect()
}

/// Build a `Machine` from a parsed QEMU command.
fn machine_from_grouped(g: &Grouped, boot_mode: &str, tdvf_before_202411: bool) -> Machine {
    let memory = g
        .memory
        .as_ref()
        .and_then(|m| m.get("size"))
        .cloned()
        // QEMU's default guest RAM size when `-m` is omitted.
        .unwrap_or_else(|| "128M".to_string());
    let bios = g.bios.clone().unwrap_or_else(|| BIOS_PLACEHOLDER.to_string());

    let qemu_options = QemuOptions {
        memory,
        bios,
        // Always emit an explicit `-smp`: when the command line omits it, QEMU
        // defaults to a single CPU. Encoding that here keeps the generated
        // metadata self-describing and prevents `QemuOptions::smp_value()` from
        // falling back to an unrelated hardcoded CPU count for the ACPI dumper.
        smp: Some(
            g.smp
                .as_ref()
                .map(|m| render_props(m, "cpus"))
                .unwrap_or_else(|| "1".to_string()),
        ),
        machine: g.machine.as_ref().map(|m| render_props(m, "type")),
        cpu: g.cpu.as_ref().map(|m| render_props(m, "model")),
        accel: g.accel.as_ref().map(|m| render_props(m, "type")),
        globals: render_all(&g.globals, "property"),
        objects: render_all(&g.objects, "type"),
        numas: render_all(&g.numa, "type"),
        acpi_tables: render_all(&g.acpitables, "file"),
        netdevs: render_all(&g.netdevs, "type"),
        devices: render_all(&g.devices, "driver"),
        fw_cfg: render_all(&g.fw_cfg, "name"),
        blockdevs: Vec::new(),
        drives: Vec::new(),
        chardevs: render_all(&g.chardevs, "type"),
    };

    let indirect = boot_mode == "indirect";
    let opt = |on: bool, v: &str| on.then(|| v.to_string());
    let measure_config = MeasureConfig {
        bootmode: boot_mode.to_string(),
        tdvf_before_202411,
        secure_boot: None,
        shim_fallback: None,
        td_hob_mmio: false,
        boot_current: opt(indirect, "[Path to BootCurrent.bin]"),
        acpi_tables_bin: Some("[Path to acpi_tables_bin]".to_string()),
        rsdp: opt(indirect, "[Path to rsdp]"),
        table_loader: opt(indirect, "[Path to table_loader]"),
        boot_order: opt(indirect, "[Path to BootOrder.bin]"),
        path_boot_xxxx: opt(indirect, "[Path to Bootxxx.bin dir]"),
        kernel: None,
        initrd: None,
        cmdline: opt(indirect, "cmdline"),
        qcow2: opt(indirect, "[Path to qcow2 image]"),
        disk: None,
        rootfs: None,
        mok_list: opt(indirect, "[Path to mok_list]"),
        mok_list_trusted: opt(indirect, "[Path to mok_list_trusted]"),
        mok_list_x: opt(indirect, "[Path to mok_list_x]"),
        sbat_level: opt(indirect, "[Path to sbat_level]"),
    };

    Machine {
        qemu_options: Some(qemu_options),
        measure_config: Some(measure_config),
        metadata_path: Default::default(),
    }
}

/// Parse a QEMU command from `qemu_command` and write `metadata.json` to `output`.
///
/// With `in_guest` set this runs inside the TD: `measure_config` points at the
/// files written by `extract_config_files.py` and the kernel cmdline and boot
/// disk are taken from the running guest.
pub fn run(
    qemu_command: &Path,
    boot_mode: &str,
    tdvf_before_202411: bool,
    output: &Path,
    in_guest: Option<&GuestOptions>,
) -> Result<()> {
    run_with(qemu_command, boot_mode, tdvf_before_202411, output, in_guest, &GuestSources::default())
}

fn run_with(
    qemu_command: &Path,
    boot_mode: &str,
    tdvf_before_202411: bool,
    output: &Path,
    in_guest: Option<&GuestOptions>,
    sources: &GuestSources,
) -> Result<()> {
    let command = fs::read_to_string(qemu_command)
        .with_context(|| format!("Failed to read QEMU command: {}", qemu_command.display()))?;
    let tokens = qcparser::tokenizer::tokenize(&command);
    if !tokens.iter().any(|t| t.starts_with('-')) {
        bail!(
            "No QEMU options found in {}: the argument separators appear to be lost \
             (e.g. /proc/PID/cmdline printed to a terminal drops its NUL separators). \
             Capture it with `cp /proc/PID/cmdline FILE` or `tr '\\0' ' ' < /proc/PID/cmdline > FILE`",
            qemu_command.display()
        );
    }
    let grouped = qcparser::parse(&command);
    if grouped.bios.is_none() {
        eprintln!("warning: no -bios in the QEMU command; set qemu_options.bios to the OVMF image");
    }
    let mut machine = machine_from_grouped(&grouped, boot_mode, tdvf_before_202411);
    if let Some(opts) = in_guest {
        if boot_mode != "indirect" {
            bail!("--in-guest requires --boot-mode indirect");
        }
        let mc = machine.measure_config.as_mut().expect("measure_config is always set");
        fill_from_guest(mc, opts, sources)?;
        let bios = &machine.qemu_options.as_ref().expect("qemu_options is always set").bios;
        if !Path::new(bios).is_file() {
            eprintln!(
                "warning: bios {bios} does not exist in this TD; copy the host's OVMF image here \
                 and update qemu_options.bios (needed for MRTD/RTMR0)"
            );
        }
    }
    let json = serde_json::to_string_pretty(&machine)
        .context("Failed to serialize metadata")?;
    fs::write(output, json)
        .with_context(|| format!("Failed to write metadata: {}", output.display()))?;
    eprintln!("metadata written to {}", output.display());
    Ok(())
}

/// Options for generating metadata inside a running TD.
pub struct GuestOptions {
    /// Directory with the files written by `extract_config_files.py`.
    pub dir: PathBuf,
    /// Raw boot disk; detected from the `/boot/efi` mount when `None`.
    pub disk: Option<String>,
    /// Guest filesystem root.
    pub rootfs: String,
}

/// Roots of the running guest's kernel interfaces (overridable for tests).
struct GuestSources {
    sys: PathBuf,
    proc: PathBuf,
}

impl Default for GuestSources {
    fn default() -> Self {
        Self { sys: "/sys".into(), proc: "/proc".into() }
    }
}

/// Point `mc` at the files extracted by `extract_config_files.py` into
/// `opts.dir`, and take the kernel cmdline and boot disk from the running guest.
fn fill_from_guest(mc: &mut MeasureConfig, opts: &GuestOptions, src: &GuestSources) -> Result<()> {
    let dir = fs::canonicalize(&opts.dir)?;
    let mut missing = Vec::new();
    let mut file = |field: &mut Option<String>, name: &str, optional: bool| {
        let path = dir.join(name);
        if path.is_file() {
            *field = Some(path.to_string_lossy().into_owned());
        } else {
            missing.push(path.display().to_string());
            // Optional inputs are simply not measured when absent.
            if optional {
                *field = None;
            }
        }
    };
    file(&mut mc.acpi_tables_bin, "acpi_tables.bin", false);
    file(&mut mc.rsdp, "rsdp.bin", false);
    file(&mut mc.table_loader, "table_loader.bin", false);
    file(&mut mc.boot_order, "BootOrder.bin", false);
    // Required to tell whether this boot went through shim's fallback path.
    file(&mut mc.boot_current, "BootCurrent.bin", false);
    file(&mut mc.mok_list, "MokListRT.bin", true);
    file(&mut mc.mok_list_trusted, "MokListTrustedRT.bin", true);
    file(&mut mc.mok_list_x, "MokListXRT.bin", true);
    file(&mut mc.sbat_level, "SbatLevelRT.bin", true);
    if !missing.is_empty() {
        eprintln!(
            "warning: missing extracted files (run extract_config_files.py in {} first): {}",
            dir.display(),
            missing.join(", ")
        );
    }
    mc.path_boot_xxxx = Some(dir.to_string_lossy().into_owned());

    mc.cmdline = Some(fs::read_to_string(src.proc.join("cmdline"))?.trim().to_string());
    let disk = match opts.disk.clone().or_else(|| detect_boot_disk(src)) {
        Some(disk) => disk,
        None => bail!("could not find the disk backing /boot/efi; pass --disk"),
    };
    if std::fs::File::open(&disk).is_err() {
        eprintln!("warning: {disk} is not readable; run tdx-measure as root");
    }
    mc.disk = Some(disk);
    mc.rootfs = Some(opts.rootfs.clone());
    mc.qcow2 = None;
    Ok(())
}

/// Return the whole-disk device (e.g. `/dev/vda`) backing the ESP at `/boot/efi`.
fn detect_boot_disk(src: &GuestSources) -> Option<String> {
    let mounts = fs::read_to_string(src.proc.join("mounts")).ok()?;
    let source = mounts.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let (dev, mnt) = (f.next()?, f.next()?);
        (mnt == "/boot/efi").then_some(dev)
    })?;
    // Resolve /dev/disk/by-* symlinks to the kernel device name.
    let dev = std::fs::canonicalize(source).unwrap_or_else(|_| PathBuf::from(source));
    let name = dev.file_name()?.to_str()?.to_string();
    let block = std::fs::canonicalize(src.sys.join("class/block").join(&name)).ok()?;
    let disk = if block.join("partition").exists() {
        block.parent()?.file_name()?.to_str()?.to_string()
    } else {
        name
    };
    Some(format!("/dev/{disk}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_command_without_separators() {
        let dir = std::env::temp_dir().join(format!("gen-metadata-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cmd = dir.join("command");
        fs::write(&cmd, "/usr/bin/qemu-system-x86_64-accelkvm-m100G-smp32-bios/usr/share/ovmf/OVMF.fd").unwrap();
        let err = run(&cmd, "indirect", false, &dir.join("metadata.json"), None).unwrap_err();
        assert!(err.to_string().contains("separators"));
        assert!(!dir.join("metadata.json").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn in_guest_uses_extracted_files_and_guest_state() {
        let root = std::env::temp_dir().join(format!("gen-metadata-guest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (sys, proc, work) = (root.join("sys"), root.join("proc"), root.join("work"));
        let write = |p: PathBuf, data: &[u8]| {
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        for f in ["acpi_tables.bin", "rsdp.bin", "table_loader.bin", "BootOrder.bin", "BootCurrent.bin", "MokListRT.bin"] {
            write(work.join(f), b"x");
        }
        write(sys.join("devices/virtio1/block/vda/vda15/partition"), b"15");
        fs::create_dir_all(sys.join("class/block")).unwrap();
        std::os::unix::fs::symlink(
            sys.join("devices/virtio1/block/vda/vda15"),
            sys.join("class/block/vda15"),
        )
        .unwrap();
        write(proc.join("cmdline"), b"BOOT_IMAGE=/vmlinuz ro\n");
        write(proc.join("mounts"), b"/dev/vda1 / ext4 rw 0 0\n/dev/vda15 /boot/efi vfat rw 0 0\n");
        write(root.join("command"), b"qemu -m 16G -smp 4 -bios /OVMF.fd");

        let meta = root.join("metadata.json");
        let opts = GuestOptions { dir: work.clone(), disk: None, rootfs: "/".into() };
        let sources = GuestSources { sys, proc };
        run_with(&root.join("command"), "indirect", true, &meta, Some(&opts), &sources).unwrap();

        let machine: Machine = serde_json::from_str(&fs::read_to_string(&meta).unwrap()).unwrap();
        let qo = machine.qemu_options.unwrap();
        assert_eq!((qo.memory.as_str(), qo.smp.as_deref()), ("16G", Some("4")));
        let mc = machine.measure_config.unwrap();
        let work = fs::canonicalize(&work).unwrap();
        let file = |name: &str| Some(work.join(name).to_string_lossy().into_owned());
        assert_eq!(mc.acpi_tables_bin, file("acpi_tables.bin"));
        assert_eq!(mc.boot_current, file("BootCurrent.bin"));
        assert_eq!(mc.path_boot_xxxx, Some(work.to_string_lossy().into_owned()));
        assert_eq!(mc.mok_list, file("MokListRT.bin"));
        assert_eq!(mc.mok_list_x, None);
        assert_eq!(mc.cmdline.as_deref(), Some("BOOT_IMAGE=/vmlinuz ro"));
        assert_eq!(mc.disk.as_deref(), Some("/dev/vda"));
        assert_eq!(mc.qcow2, None);

        fs::remove_file(work.join("BootCurrent.bin")).unwrap();
        run_with(&root.join("command"), "indirect", true, &meta, Some(&opts), &sources).unwrap();
        let machine: Machine = serde_json::from_str(&fs::read_to_string(&meta).unwrap()).unwrap();
        assert_eq!(machine.measure_config.unwrap().boot_current.as_deref(), Some("[Path to BootCurrent.bin]"));

        let err = run_with(&root.join("command"), "direct", true, &meta, Some(&opts), &sources).unwrap_err();
        assert!(err.to_string().contains("indirect"));
        fs::remove_dir_all(&root).unwrap();
    }
}
