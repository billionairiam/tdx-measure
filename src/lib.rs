/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use anyhow::{anyhow, Result};

pub use machine::Machine;
pub use image::describe_gpt_event_data;

use util::{measure_log, measure_sha384};

mod acpi;
pub mod eventlog;
mod kernel;
mod image;
mod machine;
mod num;
mod secure_boot;
mod tdvf;
mod util;

/// Contains all the measurement values for TDX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr2: Vec<u8>,
}

/// QEMU launch options defining the VM shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QemuOptions {
    pub memory: String,
    pub bios: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accel: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub numas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acpi_tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub netdevs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fw_cfg: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockdevs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drives: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chardevs: Vec<String>,
}

impl QemuOptions {
    /// Whether QEMU shape fields are present (i.e. `machine` is set).
    pub fn has_qemu_shape(&self) -> bool {
        self.machine.is_some()
    }

    /// Get the CPU model (defaults to "host").
    pub fn cpu_model(&self) -> &str {
        self.cpu.as_deref().unwrap_or("host")
    }

    /// Get the accelerator (defaults to "kvm").
    pub fn accelerator(&self) -> &str {
        self.accel.as_deref().unwrap_or("kvm")
    }

    /// The `-smp` value to feed QEMU. Prefers the preserved full topology
    /// (`smp`) so the ACPI dumper reproduces the guest's MADT/SRAT exactly.
    /// When `smp` is absent, falls back to QEMU's own default of a single CPU
    /// rather than guessing a count: callers that know the real topology
    /// (`gen-metadata`, fixtures) always populate `smp`, so this fallback is
    /// only ever hit by hand-written metadata that omitted it entirely.
    pub fn smp_value(&self) -> String {
        self.smp.clone().unwrap_or_else(|| "1".to_string())
    }
}

/// Measurement-specific configuration.
/// Contains `bootmode` to distinguish direct vs indirect boot,
/// plus all inputs needed for measurement computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasureConfig {
    pub bootmode: String,
    /// True if the TDVF firmware predates the 202411 build. In that case the
    /// RTMR1 separator event is moved to the end of the RTMR0 measurement log.
    /// Defaults to true (older firmware).
    #[serde(default = "default_true")]
    pub tdvf_before_202411: bool,
    /// Overrides the `SecureBoot` UEFI variable value measured into RTMR0.
    /// By default it is derived from the OVMF image (absent when OVMF is built
    /// without Secure Boot support, otherwise from its enrolled keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    /// Overrides whether firmware boots via shim's fallback path
    /// (`\EFI\BOOT\BOOTX64.EFI` -> `fbx64.efi` -> `\EFI\ubuntu\shimx64.efi`).
    /// OVMF does this when no OS boot entry exists, i.e. when the ESP holds no
    /// `/NvVars`. By default it is detected from `boot_current` (in-guest) or
    /// from the presence of `/boot/efi/NvVars` in `qcow2` (host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim_fallback: Option<bool>,
    /// True if the VMM appends MMIO resource descriptors (32-bit PCI hole up
    /// to the APIC and the 64-bit PCI hole) to the TD HOB, as older
    /// downstream TDX QEMU builds do. Defaults to false (upstream QEMU).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub td_hob_mmio: bool,
    /// Path to the captured `BootCurrent` variable (in-guest measurement).
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub boot_current: Option<String>,
    /// Path to the generated ACPI tables binary (measurement input).
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub acpi_tables_bin: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub rsdp: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub table_loader: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub boot_order: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub path_boot_xxxx: Option<String>,
    // Direct boot fields
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub initrd: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub cmdline: Option<String>,
    // Indirect boot fields
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub qcow2: Option<String>,
    /// Raw boot disk (e.g. `/dev/vda`) used instead of `qcow2` when measuring
    /// from inside the running guest.
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub disk: Option<String>,
    /// Guest filesystem root used with `disk` (defaults to `/`).
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub rootfs: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub mok_list: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub mok_list_trusted: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub mok_list_x: Option<String>,
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub sbat_level: Option<String>,
}

impl MeasureConfig {
    pub fn is_direct_boot(&self) -> bool {
        self.bootmode == "direct"
    }
}

fn default_true() -> bool {
    true
}

fn is_none_or_empty(s: &Option<String>) -> bool {
    s.as_ref().map_or(true, |v| v.trim().is_empty())
}

/// Parse a memory size value that can be decimal or hexadecimal (with 0x prefix),
/// with optional K/M/G/T suffix. Like QEMU's `-m`, a value without a suffix is in MiB.
pub fn parse_memory_size(s: &str) -> Result<u64> {
    const MIB: u64 = 1024 * 1024;
    let s = s.trim();

    if s.is_empty() {
        return Err(anyhow!("Empty memory size"));
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = &s[2..];
        let mib = u64::from_str_radix(hex_str, 16)
            .map_err(|e| anyhow!("Invalid hexadecimal value: {}", e))?;
        return mib.checked_mul(MIB).ok_or_else(|| anyhow!("Memory size overflow"));
    }

    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<u64>()?
            .checked_mul(MIB)
            .ok_or_else(|| anyhow!("Memory size overflow"));
    }
    let len = s.len();
    let (num_part, suffix) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[0..len - 1], 1024u64),
        'm' | 'M' => (&s[0..len - 1], 1024u64 * 1024),
        'g' | 'G' => (&s[0..len - 1], 1024u64 * 1024 * 1024),
        't' | 'T' => (&s[0..len - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => return Err(anyhow!("Unknown memory size suffix")),
    };

    let num = num_part.parse::<u64>()?;
    Ok(num * suffix)
}

#[cfg(test)]
mod tests {
    use super::parse_memory_size;

    #[test]
    fn memory_size_without_suffix_is_mib() {
        assert_eq!(parse_memory_size("16384").unwrap(), 16 << 30);
        assert_eq!(parse_memory_size("0x400").unwrap(), 1 << 30);
        assert_eq!(parse_memory_size("16384M").unwrap(), parse_memory_size("16G").unwrap());
    }
}
