/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::tdvf::Tdvf;
use crate::{kernel, image, parse_memory_size, TdxMeasurements, QemuOptions, MeasureConfig};
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
            mc.path_boot_xxxx = mc.path_boot_xxxx.as_ref().map(|p| resolve(base_dir, p));
            mc.kernel = mc.kernel.as_ref().map(|p| resolve(base_dir, p));
            mc.initrd = mc.initrd.as_ref().map(|p| resolve(base_dir, p));
            mc.qcow2 = mc.qcow2.as_ref().map(|p| resolve(base_dir, p));
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
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        let (rtmr1, rtmr2) = self.measure_runtime_registers()?;

        Ok(TdxMeasurements { mrtd, rtmr0, rtmr1, rtmr2 })
    }

    pub fn measure_platform(&self) -> Result<TdxMeasurements> {
        let qo = self.qemu_options.as_ref()
            .ok_or_else(|| anyhow!("qemu_options is required for platform measurement"))?;

        let fw_data = fs::read(&qo.bios)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd().context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        Ok(TdxMeasurements {
            mrtd,
            rtmr0,
            rtmr1: vec![],
            rtmr2: vec![],
        })
    }

    pub fn measure_runtime(&self) -> Result<TdxMeasurements> {
        let (rtmr1, rtmr2) = self.measure_runtime_registers_capped()?;
        Ok(TdxMeasurements {
            mrtd: vec![],
            rtmr0: vec![],
            rtmr1,
            rtmr2,
        })
    }

    fn measure_runtime_registers(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let memory_size = self.memory_size()?;
        self.compute_rtmr1_rtmr2(memory_size)
    }

    fn measure_runtime_registers_capped(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.compute_rtmr1_rtmr2(0xb0000000)
    }

    fn compute_rtmr1_rtmr2(&self, memory_size: u64) -> Result<(Vec<u8>, Vec<u8>)> {
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

            let rtmr1 = kernel::measure_rtmr1_direct(kernel_path, initrd_path, memory_size, 0x28000, rtmr1_separator)?;
            let rtmr2 = kernel::measure_rtmr2_direct(initrd_path, cmdline)?;
            Ok((rtmr1, rtmr2))
        } else {
            let qcow2_path = mc.qcow2.as_deref()
                .ok_or_else(|| anyhow!("qcow2 is required for indirect boot"))?;
            let mok_list = mc.mok_list.as_deref();
            let mok_list_trusted = mc.mok_list_trusted.as_deref();
            let mok_list_x = mc.mok_list_x.as_deref();
            let cmdline = mc.cmdline.as_deref().unwrap_or("");

            let rtmr1 = image::measure_rtmr1_from_qcow2(qcow2_path, rtmr1_separator)?;
            let rtmr2 = image::measure_rtmr2_from_qcow2(
                qcow2_path, cmdline, mok_list, mok_list_trusted, mok_list_x,
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
