/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::tdvf::{load_boot_variable_if_exists, load_option_has_file_path, Tdvf};
use crate::{kernel, image, measure_log, parse_memory_size, TdxMeasurements, QemuOptions, MeasureConfig};
use anyhow::{Context, Result, anyhow};
use fs_err as fs;
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level machine configuration, deserializable directly from metadata.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qemu_options: Option<QemuOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measure_config: Option<MeasureConfig>,

    // CLI-injected fields, not part of the JSON schema.
    #[serde(skip)]
    pub metadata_path: PathBuf,
}

impl Machine {
    /// Load a Machine from a metadata.json file, resolving relative paths
    /// against the file's parent directory.
    pub fn from_metadata_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read metadata: {}", path.display()))?;
        let mut machine: Machine = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse metadata: {}", path.display()))?;
        let base_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        machine.metadata_path = path.to_path_buf();
        machine.resolve_paths(&base_dir);
        Ok(machine)
    }

    /// Resolve all relative paths against a base directory.
    pub fn resolve_paths(&mut self, base_dir: &Path) {
        if let Some(qo) = &mut self.qemu_options {
            qo.bios = resolve(base_dir, &qo.bios);
        }
        if let Some(mc) = &mut self.measure_config {
            mc.acpi_tables_bin = mc.acpi_tables_bin.as_ref().map(|p| resolve(base_dir, p));
            mc.rsdp = mc.rsdp.as_ref().map(|p| resolve(base_dir, p));
            mc.table_loader = mc.table_loader.as_ref().map(|p| resolve(base_dir, p));
            mc.boot_order = mc.boot_order.as_ref().map(|p| resolve(base_dir, p));
            mc.boot_current = mc.boot_current.as_ref().map(|p| resolve(base_dir, p));
            mc.path_boot_xxxx = mc.path_boot_xxxx.as_ref().map(|p| resolve(base_dir, p));
            mc.kernel = mc.kernel.as_ref().map(|p| resolve(base_dir, p));
            mc.initrd = mc.initrd.as_ref().map(|p| resolve(base_dir, p));
            mc.qcow2 = mc.qcow2.as_ref().map(|p| resolve(base_dir, p));
            mc.disk = mc.disk.as_ref().map(|p| resolve(base_dir, p));
            mc.rootfs = mc.rootfs.as_ref().map(|p| resolve(base_dir, p));
            mc.mok_list = mc.mok_list.as_ref().map(|p| resolve(base_dir, p));
            mc.mok_list_trusted = mc.mok_list_trusted.as_ref().map(|p| resolve(base_dir, p));
            mc.mok_list_x = mc.mok_list_x.as_ref().map(|p| resolve(base_dir, p));
            mc.sbat_level = mc.sbat_level.as_ref().map(|p| resolve(base_dir, p));
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if let Some(mc) = &self.measure_config {
            match mc.bootmode.as_str() {
                "direct" | "indirect" => Ok(()),
                other => Err(anyhow!("Invalid bootmode: '{}'. Must be 'direct' or 'indirect'", other)),
            }
        } else {
            Ok(())
        }
    }

    /// Whether this is direct boot mode.
    pub fn is_direct_boot(&self) -> bool {
        self.measure_config.as_ref()
            .map(|mc| mc.is_direct_boot())
            .unwrap_or(true)
    }

    /// Get command line.
    pub fn cmdline(&self) -> &str {
        self.measure_config.as_ref()
            .and_then(|mc| mc.cmdline.as_deref())
            .unwrap_or("")
    }

    /// Get parsed memory size from qemu_options.
    pub fn memory_size(&self) -> Result<u64> {
        let qo = self.qemu_options.as_ref()
            .ok_or_else(|| anyhow!("qemu_options is required"))?;
        parse_memory_size(&qo.memory)
    }

    pub fn measure(&self) -> Result<TdxMeasurements> {
        debug!("measuring machine: {self:#?}");
        let qo = self.qemu_options.as_ref()
            .ok_or_else(|| anyhow!("qemu_options is required for measurement"))?;

        let fw_data = fs::read(&qo.bios)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd().context("Failed to compute MR TD")?;
        let shim_fallback = self.shim_fallback()?;
        let rtmr0 = tdvf.rtmr0(self, shim_fallback).context("Failed to compute RTMR0")?;

        let (rtmr1, rtmr2) = self.measure_runtime_registers(shim_fallback)?;

        Ok(TdxMeasurements { mrtd, rtmr0, rtmr1, rtmr2 })
    }

    pub fn measure_platform(&self) -> Result<TdxMeasurements> {
        let qo = self.qemu_options.as_ref()
            .ok_or_else(|| anyhow!("qemu_options is required for platform measurement"))?;

        let fw_data = fs::read(&qo.bios)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd().context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self, self.shim_fallback()?).context("Failed to compute RTMR0")?;

        Ok(TdxMeasurements {
            mrtd,
            rtmr0,
            rtmr1: vec![],
            rtmr2: vec![],
        })
    }

    pub fn measure_runtime(&self) -> Result<TdxMeasurements> {
        let (rtmr1, rtmr2) = self.measure_runtime_registers_capped(self.shim_fallback()?)?;
        Ok(TdxMeasurements {
            mrtd: vec![],
            rtmr0: vec![],
            rtmr1,
            rtmr2,
        })
    }

    fn measure_runtime_registers(&self, shim_fallback: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let memory_size = self.memory_size()?;
        self.compute_rtmr1_rtmr2(memory_size, shim_fallback)
    }

    fn measure_runtime_registers_capped(&self, shim_fallback: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        self.compute_rtmr1_rtmr2(0xb0000000, shim_fallback)
    }

    /// Where the indirect-boot chain is read from: `qcow2` (host) or `disk` (in-guest).
    fn image_source(&self) -> Result<image::ImageSource<'_>> {
        let mc = self.measure_config.as_ref()
            .ok_or_else(|| anyhow!("measure_config is required for runtime measurement"))?;
        match (mc.qcow2.as_deref(), mc.disk.as_deref()) {
            (Some(_), Some(_)) => Err(anyhow!("qcow2 and disk are mutually exclusive for indirect boot")),
            (Some(qcow2), None) => Ok(image::ImageSource::Qcow2(qcow2)),
            (None, Some(disk)) => Ok(image::ImageSource::Local {
                disk,
                rootfs: mc.rootfs.as_deref().unwrap_or("/"),
            }),
            (None, None) => Err(anyhow!("indirect boot requires either qcow2 (host) or disk (in-guest)")),
        }
    }

    /// The EV_EFI_GPT_EVENT data (EFI_GPT_DATA) measured into RTMR1 for indirect boot.
    pub fn gpt_event_data(&self) -> Result<Vec<u8>> {
        image::extract_gpt_event_data(&self.image_source()?)
    }

    /// Whether firmware boots via shim's fallback path
    /// (`\EFI\BOOT\BOOTX64.EFI` -> `fbx64.efi` -> `shimx64.efi`).
    ///
    /// OVMF falls back to the removable-media path when no OS boot entry
    /// exists, which is the case whenever the ESP holds no `/NvVars` (the file
    /// OVMF persists UEFI variables to).
    pub fn shim_fallback(&self) -> Result<bool> {
        let Some(mc) = self.measure_config.as_ref() else {
            return Ok(false);
        };
        if mc.is_direct_boot() {
            return Ok(false);
        }
        if let Some(fallback) = mc.shim_fallback {
            return Ok(fallback);
        }
        // In-guest: the current boot fell back iff the entry firmware booted
        // is a firmware-generated one (no file path node).
        if let Some(path) = mc.boot_current.as_deref() {
            let data = fs::read(path)?;
            if data.len() < 2 {
                return Err(anyhow!("BootCurrent data in {path} is too short"));
            }
            let num = u16::from_le_bytes([data[0], data[1]]);
            let option = load_boot_variable_if_exists(num, self)?
                .ok_or_else(|| anyhow!("Boot{num:04X}.bin (BootCurrent) not found in path_boot_xxxx"))?;
            let fallback = !load_option_has_file_path(&option);
            debug!("BootCurrent is Boot{num:04X}, shim_fallback={fallback}");
            return Ok(fallback);
        }
        // Host: predict the next boot from the image.
        if let Ok(source @ image::ImageSource::Qcow2(_)) = self.image_source() {
            let fallback = !source.file_exists("/boot/efi/NvVars")?;
            debug!("/boot/efi/NvVars {}, shim_fallback={fallback}", if fallback { "absent" } else { "present" });
            return Ok(fallback);
        }
        Ok(false)
    }

    fn compute_rtmr1_rtmr2(&self, memory_size: u64, shim_fallback: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rtmr1_log, rtmr2_log) = self.rtmr1_rtmr2_logs(memory_size, shim_fallback)?;
        Ok((measure_log(&rtmr1_log), measure_log(&rtmr2_log)))
    }

    /// Expected event digests for RTMR0, RTMR1 and RTMR2, in measurement order.
    pub fn rtmr_event_logs(&self) -> Result<[Vec<Vec<u8>>; 3]> {
        let qo = self.qemu_options.as_ref()
            .ok_or_else(|| anyhow!("qemu_options is required for measurement"))?;
        let fw_data = fs::read(&qo.bios)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let shim_fallback = self.shim_fallback()?;
        let rtmr0 = tdvf.rtmr0_log(self, shim_fallback).context("Failed to compute RTMR0")?;
        let (rtmr1, rtmr2) = self.rtmr1_rtmr2_logs(self.memory_size()?, shim_fallback)?;
        Ok([rtmr0, rtmr1, rtmr2])
    }

    /// Local path of the initrd measured into RTMR2, if it is a local file.
    pub fn initrd_path(&self) -> Result<Option<PathBuf>> {
        let mc = self.measure_config.as_ref()
            .ok_or_else(|| anyhow!("measure_config is required"))?;
        if mc.is_direct_boot() {
            return Ok(mc.initrd.as_ref().map(PathBuf::from));
        }
        match self.image_source()? {
            image::ImageSource::Local { rootfs, .. } => {
                let guest = image::initrd_guest_path(mc.cmdline.as_deref().unwrap_or(""))?;
                Ok(Some(Path::new(rootfs).join(guest.trim_start_matches('/'))))
            }
            image::ImageSource::Qcow2(_) => Ok(None),
        }
    }

    fn rtmr1_rtmr2_logs(&self, memory_size: u64, shim_fallback: bool) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let mc = self.measure_config.as_ref()
            .ok_or_else(|| anyhow!("measure_config is required for runtime measurement"))?;
        // Older TDVF (<202411) moves the RTMR1 separator into RTMR0.
        let rtmr1_separator = !mc.tdvf_before_202411;

        if mc.is_direct_boot() {
            let kernel_path = mc.kernel.as_deref()
                .ok_or_else(|| anyhow!("kernel is required for direct boot"))?;
            let initrd_path = mc.initrd.as_deref()
                .ok_or_else(|| anyhow!("initrd is required for direct boot"))?;
            let cmdline = mc.cmdline.as_deref().unwrap_or("");

            let rtmr1 = kernel::rtmr1_log_direct(kernel_path, initrd_path, memory_size, 0x28000, rtmr1_separator)?;
            let rtmr2 = kernel::rtmr2_log_direct(initrd_path, cmdline)?;
            Ok((rtmr1, rtmr2))
        } else {
            let source = self.image_source()?;
            let mok_list = mc.mok_list.as_deref();
            let mok_list_trusted = mc.mok_list_trusted.as_deref();
            let mok_list_x = mc.mok_list_x.as_deref();
            let cmdline = mc.cmdline.as_deref().unwrap_or("");

            let rtmr1 = image::rtmr1_log_from_image(&source, rtmr1_separator, shim_fallback)?;
            let rtmr2 = image::rtmr2_log_from_image(
                &source, cmdline, mok_list, mok_list_trusted, mok_list_x, shim_fallback,
            )?;
            Ok((rtmr1, rtmr2))
        }
    }
}

/// Resolve a potentially relative path against a base directory.
/// Returns the path as-is if it's already absolute.
fn resolve(base: &Path, path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        base.join(path).display().to_string()
    }
}
