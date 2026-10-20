/*
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

//! Generate a `metadata.json` (Machine) from a raw QEMU command line.

use anyhow::{Context, Result};
use fs_err as fs;
use qcparser::{Grouped, Props};
use std::path::Path;
use tdx_measure::{Machine, MeasureConfig, QemuOptions};

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
        .unwrap_or_else(|| "2G".to_string());
    let bios = g.bios.clone().unwrap_or_default();

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
        acpi_tables_bin: Some("[Path to acpi_tables_bin]".to_string()),
        rsdp: opt(indirect, "[Path to rsdp]"),
        table_loader: opt(indirect, "[Path to table_loader]"),
        boot_order: opt(indirect, "[Path to BootOrder.bin]"),
        path_boot_xxxx: opt(indirect, "[Path to Bootxxx.bin dir]"),
        kernel: None,
        initrd: None,
        cmdline: opt(indirect, "cmdline"),
        qcow2: opt(indirect, "[Path to qcow2 image]"),
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
pub fn run(qemu_command: &Path, boot_mode: &str, tdvf_before_202411: bool, output: &Path) -> Result<()> {
    let command = fs::read_to_string(qemu_command)
        .with_context(|| format!("Failed to read QEMU command: {}", qemu_command.display()))?;
    let grouped = qcparser::parse(&command);
    let machine = machine_from_grouped(&grouped, boot_mode, tdvf_before_202411);
    let json = serde_json::to_string_pretty(&machine)
        .context("Failed to serialize metadata")?;
    fs::write(output, json)
        .with_context(|| format!("Failed to write metadata: {}", output.display()))?;
    eprintln!("metadata written to {}", output.display());
    Ok(())
}
