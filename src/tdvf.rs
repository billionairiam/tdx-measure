/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, warn};
use sha2::{Digest, Sha384};

use crate::num::read_le;
use crate::secure_boot::SecureBootVars;
use crate::util::{debug_print_log, measure_sha384, measure_log, utf16_encode, read_file_data};
use crate::Machine;

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_GRANULARITY: usize = 0x100;

const ATTRIBUTE_MR_EXTEND: u32 = 0x00000001;
const ATTRIBUTE_PAGE_AUG: u32 = 0x00000002;

const TDVF_SECTION_TD_CFV: u32 = 0x01;
const TDVF_SECTION_TD_HOB: u32 = 0x02;
const TDVF_SECTION_TEMP_MEM: u32 = 0x03;

#[derive(Debug)]
struct TdvfSection {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    sec_type: u32,
    attributes: u32,
}

#[derive(Debug)]
pub(crate) struct Tdvf<'a> {
    fw: &'a [u8],
    sections: Vec<TdvfSection>,
}

/// Encodes a GUID string into its binary representation.
fn encode_guid(guid_str: &str) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(16);
    let atoms: Vec<&str> = guid_str.split('-').collect();

    if atoms.len() != 5 {
        return Err(anyhow!("Invalid GUID format"));
    }

    for (idx, atom) in atoms.iter().enumerate() {
        let raw = hex::decode(atom).context("Failed to decode hex in GUID")?;

        if idx <= 2 {
            // Little-endian: reverse the bytes
            for i in (0..raw.len()).rev() {
                data.push(raw[i]);
            }
        } else {
            // Big-endian: keep as-is
            data.extend_from_slice(&raw);
        }
    }

    Ok(data)
}

/// Measures an EFI variable event.
fn measure_tdx_efi_variable(vendor_guid: &str, var_name: &str, var_data: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.extend_from_slice(&encode_guid(vendor_guid)?);
    data.extend_from_slice(&(var_name.len() as u64).to_le_bytes());

    // Include variable data size
    let data_size = var_data.map_or(0, |d| d.len()) as u64;
    data.extend_from_slice(&data_size.to_le_bytes());

    // Add variable name (UTF-16 encoded)
    data.extend(utf16_encode(var_name));

    // Add variable data if present
    if let Some(var_data) = var_data {
        data.extend_from_slice(var_data);
    }

    Ok(measure_sha384(&data))
}

/// Loads boot order data and parses boot entry numbers based on boot mode.
/// For direct boot, returns a simulated boot order with no boot entries.
/// For indirect boot, reads the boot order file and extracts the list of boot entry numbers.
fn parse_boot_order(machine: &Machine, shim_fallback: bool) -> Result<(Vec<u8>, Vec<u16>)> {
    if machine.is_direct_boot() {
        // Direct boot: simulated boot order data
        Ok((vec![0, 0], Vec::new()))
    } else {
        let boot_order_path = machine.measure_config.as_ref()
            .and_then(|mc| mc.boot_order.as_deref())
            .unwrap_or("");
        if !boot_order_path.is_empty() {
            // Indirect boot: read and parse the boot order file
            let boot_order_data = read_file_data(boot_order_path)?;

            // Validate and parse boot order data
            if boot_order_data.len() % 2 != 0 {
                bail!("BootOrder data length must be even (array of UINT16s)");
            }

            let mut boot_entries = Vec::new();
            for chunk in boot_order_data.chunks(2) {
                let entry_num = u16::from_le_bytes([chunk[0], chunk[1]]);
                boot_entries.push(entry_num);
            }

            // On a fallback boot, firmware measured BootOrder before fbx64.efi
            // added the OS entries that the runtime capture now contains.
            // Firmware-generated entries never carry a file path node.
            if shim_fallback {
                let mut kept = Vec::new();
                for num in boot_entries {
                    match load_boot_variable_if_exists(num, machine)? {
                        Some(data) if load_option_has_file_path(&data) => {
                            debug!("Dropping Boot{num:04X} from BootOrder (created by shim fallback)");
                        }
                        _ => kept.push(num),
                    }
                }
                let boot_order_data = kept.iter().flat_map(|n| n.to_le_bytes()).collect();
                return Ok((boot_order_data, kept));
            }

            Ok((boot_order_data, boot_entries))
        } else {
            Err(anyhow!("Boot order file is required for indirect boot"))
        }
    }
}

/// Whether an EFI_LOAD_OPTION's device path contains a MEDIA_FILEPATH_DP node.
pub(crate) fn load_option_has_file_path(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    let path_len = u16::from_le_bytes([data[4], data[5]]) as usize;
    // Skip the NUL-terminated UTF-16 description.
    let mut off = 6;
    while off + 1 < data.len() && (data[off] != 0 || data[off + 1] != 0) {
        off += 2;
    }
    off += 2;
    let end = (off + path_len).min(data.len());
    while off + 4 <= end {
        let (ty, sub) = (data[off], data[off + 1]);
        let len = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
        if ty == 0x7f && sub == 0xff {
            break;
        }
        if ty == 0x04 && sub == 0x04 {
            return true;
        }
        if len < 4 {
            break;
        }
        off += len;
    }
    false
}

/// Loads boot variable data if the corresponding file exists
pub(crate) fn load_boot_variable_if_exists(boot_entry_num: u16, machine: &Machine) -> Result<Option<Vec<u8>>> {
    let path_boot_xxxx = machine.measure_config.as_ref()
        .and_then(|mc| mc.path_boot_xxxx.as_deref())
        .unwrap_or("");
    let filename = format!("{}/Boot{:04X}.bin", path_boot_xxxx, boot_entry_num);
    // Try to read the file, return None if it doesn't exist
    match read_file_data(&filename) {
        Ok(data) => Ok(Some(data)),
        Err(_) => {
            // File doesn't exist or can't be read, skip this boot entry
            Ok(None)
        }
    }
}

impl<'a> Tdvf<'a> {
    pub fn parse(fw: &'a [u8]) -> Result<Tdvf<'a>> {
        const TDX_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
        const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
        const BYTES_AFTER_TABLE_FOOTER: usize = 32;

        let offset = fw.len() - BYTES_AFTER_TABLE_FOOTER;
        let encoded_footer_guid = encode_guid(TABLE_FOOTER_GUID)?;
        let guid = &fw[offset - 16..offset];

        if guid != encoded_footer_guid {
            bail!("Failed to parse TDVF metadata: Invalid footer GUID");
        }

        let tables_len =
            u16::from_le_bytes(fw[offset - 18..offset - 16].try_into().unwrap()) as usize;
        if tables_len == 0 || tables_len > offset - 18 {
            bail!("Failed to parse TDVF metadata: Invalid tables length");
        }
        let tables = &fw[offset - 18 - tables_len..offset - 18];
        let mut offset = tables.len();

        let mut data: Option<&[u8]> = None;
        let encoded_guid = encode_guid(TDX_METADATA_OFFSET_GUID)?;
        loop {
            if offset < 18 {
                break;
            }
            let guid = &tables[offset - 16..offset];
            let entry_len = read_le::<u16>(tables, offset - 18, "entry length")? as usize;
            if entry_len > offset - 18 {
                bail!("Failed to parse TDVF metadata: Invalid entry length");
            }
            if guid == encoded_guid {
                data = Some(&tables[offset - 18 - entry_len..offset - 18]);
                break;
            }
            offset -= entry_len;
        }

        let data = data.context("Failed to parse TDVF metadata: Missing TDVF metadata")?;

        let tdvf_meta_offset =
            u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap()) as usize;
        let tdvf_meta_offset = fw.len() - tdvf_meta_offset;
        let tdvf_meta_desc = &fw[tdvf_meta_offset..tdvf_meta_offset + 16];

        if &tdvf_meta_desc[..4] != b"TDVF" {
            bail!("Failed to parse TDVF metadata: Invalid TDVF descriptor");
        }
        let tdvf_version = u32::from_le_bytes(tdvf_meta_desc[8..12].try_into().unwrap());
        if tdvf_version != 1 {
            bail!("Failed to parse TDVF metadata: Unsupported TDVF version");
        }
        let num_sections = u32::from_le_bytes(tdvf_meta_desc[12..16].try_into().unwrap()) as usize;

        let mut meta = Tdvf {
            fw,
            sections: Vec::new(),
        };
        for i in 0..num_sections {
            let sec_offset = tdvf_meta_offset + 16 + 32 * i;
            let sec_data = &fw[sec_offset..sec_offset + 32];
            let s = TdvfSection {
                data_offset: u32::from_le_bytes(sec_data[0..4].try_into().unwrap()),
                raw_data_size: u32::from_le_bytes(sec_data[4..8].try_into().unwrap()),
                memory_address: u64::from_le_bytes(sec_data[8..16].try_into().unwrap()),
                memory_data_size: u64::from_le_bytes(sec_data[16..24].try_into().unwrap()),
                sec_type: u32::from_le_bytes(sec_data[24..28].try_into().unwrap()),
                attributes: u32::from_le_bytes(sec_data[28..32].try_into().unwrap()),
            };

            if s.memory_address % PAGE_SIZE != 0 {
                bail!("Failed to parse TDVF metadata: Section memory address not aligned");
            }
            if s.memory_data_size < s.raw_data_size as u64 {
                bail!("Failed to parse TDVF metadata: Section memory data size less than raw");
            }
            if s.memory_data_size % PAGE_SIZE != 0 {
                bail!("Failed to parse TDVF metadata: Section memory data size not aligned");
            }
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0
                && s.raw_data_size as u64 > s.memory_data_size
            {
                bail!("Failed to parse TDVF metadata: Section raw data size less than memory");
            }

            meta.sections.push(s);
        }

        Ok(meta)
    }

    pub fn mrtd(&self) -> Result<Vec<u8>> {
        let mut h = Sha384::new();

        let mem_page_add = |h: &mut Sha384, s: &TdvfSection, page: u64| {
            if s.attributes & ATTRIBUTE_PAGE_AUG == 0 {
                let mut buf = [0u8; 128];
                buf[..12].copy_from_slice(b"MEM.PAGE.ADD");
                let gpa = s.memory_address + page * PAGE_SIZE;
                buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                h.update(buf);
            }
        };

        let mr_extend = |h: &mut Sha384, s: &TdvfSection, page: u64| {
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0 {
                for i in 0..(PAGE_SIZE as usize / MR_EXTEND_GRANULARITY) {
                    let mut buf = [0u8; 128];
                    buf[..9].copy_from_slice(b"MR.EXTEND");
                    let gpa =
                        s.memory_address + page * PAGE_SIZE + (i * MR_EXTEND_GRANULARITY) as u64;
                    buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                    h.update(buf);

                    let chunk_offset = s.data_offset as usize
                        + (page * PAGE_SIZE) as usize
                        + i * MR_EXTEND_GRANULARITY;
                    h.update(&self.fw[chunk_offset..chunk_offset + MR_EXTEND_GRANULARITY]);
                }
            }
        };

        for s in &self.sections {
            let num_pages = s.memory_data_size / PAGE_SIZE;

            for page in 0..num_pages {
                mem_page_add(&mut h, s, page);
                mr_extend(&mut h, s, page);
            }
        }
        Ok(h.finalize().to_vec())
    }

    pub fn rtmr0(&self, machine: &Machine, shim_fallback: bool) -> Result<Vec<u8>> {
        Ok(measure_log(&self.rtmr0_log(machine, shim_fallback)?))
    }

    /// RTMR0 event digests in measurement order.
    pub fn rtmr0_log(&self, machine: &Machine, shim_fallback: bool) -> Result<Vec<Vec<u8>>> {
        // Calculate measurement of the TD Hand-Off Block (TD-HOB)
        let memory_size = machine.memory_size()?;
        let td_hob_mmio = machine.measure_config.as_ref().is_some_and(|mc| mc.td_hob_mmio);
        let td_hob_hash = self.measure_td_hob(memory_size, td_hob_mmio)?;

        // Calculate measurement of the Configuration Firmware Volume (CFV)
        let cfv_hash = self.measure_cfv().context("Failed to find CFV section")?;

        // Build ACPI tables
        let tables = machine.build_tables()?;
        let acpi_tables_hash = measure_sha384(&tables.tables);
        let acpi_rsdp_hash = measure_sha384(&tables.rsdp);
        let acpi_loader_hash = measure_sha384(&tables.loader);

        // Load boot order data and entries
        let (boot_order_data, boot_entries) = parse_boot_order(machine, shim_fallback)?;

        // Secure Boot variables as initialized from the firmware's CFV variable store.
        let mut sb = SecureBootVars::from_firmware(self.fw, self.cfv()?);
        if let Some(enabled) = machine.measure_config.as_ref().and_then(|mc| mc.secure_boot) {
            sb.secure_boot = Some(enabled as u8);
        }
        debug!("Secure Boot variables: SecureBoot={:?} PK={} KEK={} db={} dbx={} dbt={}",
            sb.secure_boot, sb.pk.is_some(), sb.kek.is_some(), sb.db.is_some(), sb.dbx.is_some(), sb.dbt.is_some());
        if sb.secure_boot == Some(1) {
            warn!("Secure Boot is enabled; image verification (EV_EFI_VARIABLE_AUTHORITY) events are not modeled");
        }

        // Compute RTMR0 log
        let mut rtmr0_log = vec![
            td_hob_hash,
            cfv_hash,
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "SecureBoot", sb.secure_boot.as_ref().map(std::slice::from_ref))?,
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "PK", sb.pk.as_deref())?,
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "KEK", sb.kek.as_deref())?,
            measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "db", sb.db.as_deref())?,
            measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbx", sb.dbx.as_deref())?,
        ];
        // dbt is only measured when present.
        if let Some(dbt) = sb.dbt.as_deref() {
            rtmr0_log.push(measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbt", Some(dbt))?);
        }
        rtmr0_log.extend([
            measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
            acpi_loader_hash,
            acpi_rsdp_hash,
            acpi_tables_hash,
            measure_sha384(&boot_order_data), // Always measure BootOrder itself
        ]);

        if machine.is_direct_boot() {
            // Boot0000 data for direct boot mode
            let boot0000_hex = "090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400";
            let boot0000 = hex::decode(boot0000_hex).context("Failed to decode boot0000 hex string")?;
            rtmr0_log.push(measure_sha384(&boot0000));
        } else {
            for boot_entry_num in boot_entries {
                if let Some(boot_data) = load_boot_variable_if_exists(boot_entry_num, machine)? {
                    rtmr0_log.push(measure_sha384(&boot_data));
                }
            }
        }

        // TDVF firmware before the 202411 build appends a trailing separator.
        let before_202411 = machine.measure_config.as_ref()
            .map(|mc| mc.tdvf_before_202411)
            .unwrap_or(false);
        if before_202411 {
            rtmr0_log.push(measure_sha384(&[0x00, 0x00, 0x00, 0x00])); // Separator
        }

        // Add SbatLevel if not direct boot; shim measures it on every run, and
        // with fallback shim runs twice (BOOTX64.EFI, then shimx64.efi).
        if !machine.is_direct_boot() {
            let shim_runs = if shim_fallback { 2 } else { 1 };
            for _ in 0..shim_runs {
                rtmr0_log.push(measure_tdx_efi_variable("605DAB50-E046-4300-ABB6-3DD810DD8B23", "SbatLevel", Some(b"sbat,1,2021030218\n"))?);
            }
        }

        debug_print_log("RTMR0", &rtmr0_log);
        Ok(rtmr0_log)
    }

    fn measure_td_hob(&self, memory_size: u64, mmio: bool) -> Result<Vec<u8>> {
        let mut memory_acceptor = MemoryAcceptor::new(0, memory_size);
        let mut td_hob = Vec::new();

        let mut td_hob_base_addr = 0x809000u64;
        for s in &self.sections {
            if let TDVF_SECTION_TD_HOB | TDVF_SECTION_TEMP_MEM = s.sec_type {
                memory_acceptor.accept(s.memory_address, s.memory_address + s.memory_data_size);
            }
            if s.sec_type == TDVF_SECTION_TD_HOB {
                td_hob_base_addr = s.memory_address;
            }
        }

        td_hob.extend_from_slice(&[0x01, 0x00]); // HobType
        td_hob.extend_from_slice(&56u16.to_le_bytes()); // HobLength
        td_hob.extend_from_slice(&[0u8; 4]); // Reserved
        td_hob.extend_from_slice(&9u32.to_le_bytes()); // Version
        td_hob.extend_from_slice(&[0u8; 4]); // BootMode
        td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryTop
        td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryBottom
        td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryTop
        td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryBottom
        td_hob.extend_from_slice(&[0u8; 8]); // EfiEndOfHobList (placeholder)

        let mut add_resource_hob = |resource_type: u8, attribute: u32, start: u64, length: u64| {
            td_hob.extend_from_slice(&[0x03, 0x00]); // HobType
            td_hob.extend_from_slice(&48u16.to_le_bytes()); // HobLength
            td_hob.extend_from_slice(&[0u8; 4]); // Reserved
            td_hob.extend_from_slice(&[0u8; 16]); // Owner
            td_hob.extend_from_slice(&resource_type.to_le_bytes());
            td_hob.extend_from_slice(&[0u8; 3]); // Padding for resource type
            td_hob.extend_from_slice(&attribute.to_le_bytes()); // ResourceAttribute
            td_hob.extend_from_slice(&start.to_le_bytes());
            td_hob.extend_from_slice(&length.to_le_bytes());
        };
        let mut add_memory_resource_hob =
            |resource_type: u8, start: u64, length: u64| add_resource_hob(resource_type, 7, start, length);

        let (_, last_start, last_end) = memory_acceptor.ranges.pop().expect("No ranges");

        for (accepted, start, end) in memory_acceptor.ranges {
            if accepted {
                add_memory_resource_hob(0x00, start, end - start);
            } else {
                add_memory_resource_hob(0x07, start, end - start);
            }
        }

        if memory_size >= 0xB0000000 {
            add_memory_resource_hob(0x07, last_start, 0x80000000u64 - last_start);
            add_memory_resource_hob(0x07, 0x100000000, last_end - 0x80000000u64);
        } else {
            add_memory_resource_hob(0x07, last_start, last_end - last_start);
        }

        if mmio {
            const GIB: u64 = 1 << 30;
            const APIC_DEFAULT_ADDRESS: u64 = 0xFEE0_0000;
            const PCI_HOLE64_SIZE: u64 = 32 * GIB; // q35 default
            const MMIO_ATTRIBUTE: u32 = 0x403; // PRESENT | INITIALIZED | UNCACHEABLE
            let below_4g = if memory_size >= 0xB0000000 { 0x80000000 } else { memory_size };
            let hole64_start = (0x100000000 + memory_size - below_4g).div_ceil(GIB) * GIB;
            add_resource_hob(0x01, MMIO_ATTRIBUTE, below_4g, APIC_DEFAULT_ADDRESS - below_4g);
            add_resource_hob(0x01, MMIO_ATTRIBUTE, hole64_start, PCI_HOLE64_SIZE);
        }

        let end_of_hob_list = td_hob_base_addr + td_hob.len() as u64 + 8;
        td_hob[48..56].copy_from_slice(&end_of_hob_list.to_le_bytes());

        Ok(measure_sha384(&td_hob))
    }

    fn measure_cfv(&self) -> Result<Vec<u8>> {
        Ok(measure_sha384(self.cfv()?))
    }

    /// Raw bytes of the CFV section (the pristine UEFI variable store).
    fn cfv(&self) -> Result<&'a [u8]> {
        for section in &self.sections {
            if section.sec_type == TDVF_SECTION_TD_CFV {
                let start = section.data_offset as usize;
                let end = start + section.raw_data_size as usize;

                if end > self.fw.len() {
                    return Err(anyhow!("CFV section extends beyond firmware data."));
                }

                return Ok(&self.fw[start..end]);
            }
        }

        Err(anyhow!("CFV section does not exist."))
    }
}

struct MemoryAcceptor {
    ranges: Vec<(bool, u64, u64)>,
}

impl MemoryAcceptor {
    fn new(start: u64, size: u64) -> Self {
        Self {
            ranges: vec![(false, start, start + size)],
        }
    }

    fn accept(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        let mut new_ranges = Vec::new();

        for &(is_accepted, range_start, range_end) in &self.ranges {
            if is_accepted || range_end <= start || range_start >= end {
                new_ranges.push((is_accepted, range_start, range_end));
            } else {
                if range_start < start {
                    new_ranges.push((false, range_start, start));
                }
                if range_end > end {
                    new_ranges.push((false, end, range_end));
                }
            }
        }
        new_ranges.push((true, start, end));
        new_ranges.sort_by_key(|&(_, start, _)| start);
        self.ranges = new_ranges;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn td_hob_with_mmio_resources() {
        // TdxTable digests from a TD event log (16G, Ubuntu OVMF layout) of a
        // VMM that appends MMIO resource HOBs, and the upstream QEMU layout.
        let section = |memory_address, memory_data_size, sec_type| TdvfSection {
            data_offset: 0, raw_data_size: 0, memory_address, memory_data_size, sec_type, attributes: 0,
        };
        let tdvf = Tdvf {
            fw: &[],
            sections: vec![
                section(0x800000, 0x6000, TDVF_SECTION_TEMP_MEM),
                section(0x809000, 0x2000, TDVF_SECTION_TD_HOB),
                section(0x80b000, 0x2000, TDVF_SECTION_TEMP_MEM),
                section(0x810000, 0x10000, TDVF_SECTION_TEMP_MEM),
            ],
        };
        assert_eq!(
            hex::encode(tdvf.measure_td_hob(16 << 30, true).unwrap()),
            "18a0a0201e013689dc6d05735ff9c0a063282af439ce31e4afa84acc6eb014089903a798339ed342fd9cf08d06a848d0"
        );
        assert_eq!(
            hex::encode(tdvf.measure_td_hob(16 << 30, false).unwrap()),
            "cd2312a0d87ef3c4a928df87088969a80b33d7bf3fc584bdde637b09ed808a8d821a56b78a13a6eb506db7578444abbe"
        );
    }

    #[test]
    fn secure_boot_disabled_is_measured_as_one_byte() {
        // EV_EFI_VARIABLE_DRIVER_CONFIG for SecureBoot from a TD event log
        // (OVMF built with Secure Boot support, Secure Boot disabled).
        let digest = measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "SecureBoot", Some(&[0])).unwrap();
        assert_eq!(
            hex::encode(digest),
            "cfa4e2c606f572627bf06d5669cc2ab1128358d27b45bc63ee9ea56ec109cfafb7194006f847a6a74b5eaed6b73332ec"
        );
    }

    // Firmware-generated "UEFI Misc Device" entry (from a real TD event log).
    const MISC_DEVICE: &str = "010000002200550045004600490020004d006900730063002000440065007600690063006500000002010c00d041030a000000000101060000020101060000000101060000017fff04004eac0881119f594d850ee21a522c59b2";

    /// Entry created by shim fallback: HD(...)/\EFI\ubuntu\shimx64.efi
    fn ubuntu_boot_option() -> Vec<u8> {
        let file: Vec<u8> = utf16_encode("\\EFI\\ubuntu\\shimx64.efi").into_iter().chain([0, 0]).collect();
        let mut path = vec![0x04, 0x01, 42, 0];
        path.extend([0u8; 38]);
        path.extend([0x04, 0x04]);
        path.extend(((file.len() + 4) as u16).to_le_bytes());
        path.extend(&file);
        path.extend([0x7f, 0xff, 0x04, 0x00]);
        let mut option = vec![1, 0, 0, 0];
        option.extend((path.len() as u16).to_le_bytes());
        option.extend(utf16_encode("Ubuntu"));
        option.extend([0, 0]);
        option.extend(&path);
        option
    }

    #[test]
    fn load_option_file_path_detection() {
        let ui_app = hex::decode("090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400").unwrap();
        assert!(!load_option_has_file_path(&hex::decode(MISC_DEVICE).unwrap()));
        assert!(!load_option_has_file_path(&ui_app));
        assert!(load_option_has_file_path(&ubuntu_boot_option()));
    }

    #[test]
    fn shim_fallback_detected_from_boot_current() {
        let dir = std::env::temp_dir().join(format!("tdx_measure_boot_current_{}", std::process::id()));
        fs_err::create_dir_all(&dir).unwrap();
        fs_err::write(dir.join("Boot0001.bin"), hex::decode(MISC_DEVICE).unwrap()).unwrap();
        fs_err::write(dir.join("Boot0007.bin"), ubuntu_boot_option()).unwrap();
        let machine_with = |boot_current: u16| -> Machine {
            fs_err::write(dir.join("BootCurrent.bin"), boot_current.to_le_bytes()).unwrap();
            serde_json::from_value(serde_json::json!({
                "measure_config": {
                    "bootmode": "indirect",
                    "path_boot_xxxx": dir.to_str().unwrap(),
                    "boot_current": dir.join("BootCurrent.bin").to_str().unwrap(),
                }
            })).unwrap()
        };
        let fallback = machine_with(0x0001).shim_fallback();
        let normal = machine_with(0x0007).shim_fallback();
        let _ = fs_err::remove_dir_all(&dir);
        assert!(fallback.unwrap());
        assert!(!normal.unwrap());
    }
}
