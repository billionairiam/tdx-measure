/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Parse the QEMU `etc/acpi/tables` blob and derive the `etc/acpi/rsdp` and
//! `etc/table-loader` companions the guest firmware measures into RTMR0.

use anyhow::{anyhow, bail, Result};

use crate::util::read_file_data;
use crate::Machine;

const LDR_LENGTH: usize = 4096;
const FIXED_STRING_LEN: usize = 56;

pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine {
    pub fn build_tables(&self) -> Result<Tables> {
        let mc = self.measure_config.as_ref()
            .ok_or_else(|| anyhow!("measure_config is required to build ACPI tables"))?;

        let tables = read_file_data(&mc.acpi_tables_bin.as_ref().unwrap_or(&"".to_string()))?;

        let rsdp: Vec<u8> = match &mc.rsdp {
            Some(path) if !path.is_empty() => read_file_data(path)?,
            _ => {
                let (rsdt_offset, _rsdt_csum, _rsdt_len) = find_acpi_table(&tables, "RSDT")?;
                let mut rsdp = Vec::with_capacity(20);
                rsdp.extend_from_slice(b"RSD PTR "); // Signature
                rsdp.push(0x00); // Checksum placeholder
                rsdp.extend_from_slice(b"BOCHS "); // OEM ID
                rsdp.push(0x00); // Revision
                rsdp.extend_from_slice(&rsdt_offset.to_le_bytes()); // RSDT Address
                rsdp
            }
        };

        let loader: Vec<u8> = match &mc.table_loader {
            Some(path) if !path.is_empty() => read_file_data(path)?,
            _ => derive_table_loader(&tables)?,
        };

        Ok(Tables {
            tables,
            rsdp,
            loader,
        })
    }
}

/// Walks the concatenated ACPI tables blob exposed by QEMU via `etc/acpi/tables`
/// and returns one entry per System Description Table found in it, in file order.
/// Each tuple is `(signature, offset, csum_offset, length)` where `csum_offset`
/// is the byte offset of the table's `Checksum` field (header offset 9).
fn list_acpi_tables(tables: &[u8]) -> Result<Vec<([u8; 4], u32, u32, u32)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= tables.len() {
        let sig: [u8; 4] = tables[off..off + 4].try_into().unwrap();
        if !sig.iter().all(|b| (32..127).contains(b)) {
            break;
        }
        let len = u32::from_le_bytes(tables[off + 4..off + 8].try_into().unwrap()) as usize;
        if len < 8 || off + len > tables.len() {
            bail!("ACPI table at offset {off:#x} has invalid length {len}");
        }
        out.push((sig, off as u32, (off + 9) as u32, len as u32));
        off += len;
    }
    Ok(out)
}

/// Build the QEMU table-loader blob (`etc/table-loader`) from a concatenated ACPI
/// tables image. The command order mirrors what QEMU's `acpi_build` emits today:
///   Allocate rsdp + Allocate tables
///   AddChecksum DSDT
///   AddPtr FACP→FACS, FACP→DSDT (4-byte), FACP→DSDT (8-byte X_DSDT)
///   AddChecksum FACP
///   AddChecksum {APIC, HPET, MCFG, WAET, ...} in file order
///   AddPtr RSDT→entry_i for each 4-byte entry (one per non-DSDT table)
///   AddChecksum RSDT
///   AddPtr RSDP→RSDT, AddChecksum RSDP
fn derive_table_loader(tables: &[u8]) -> Result<Vec<u8>> {
    const TABLES_FILE: &str = "etc/acpi/tables";
    const RSDP_FILE: &str = "etc/acpi/rsdp";

    let list = list_acpi_tables(tables)?;

    let find = |sig: &str| -> Result<(u32, u32, u32)> {
        list.iter()
            .find(|(s, ..)| s.as_slice() == sig.as_bytes())
            .map(|&(_, off, csum, len)| (off, csum, len))
            .ok_or_else(|| anyhow!("Required ACPI table missing: {sig}"))
    };
    let (dsdt_offset, dsdt_csum, dsdt_len) = find("DSDT")?;
    let (facp_offset, facp_csum, facp_len) = find("FACP")?;
    let (rsdt_offset, rsdt_csum, rsdt_len) = find("RSDT")?;

    let mut loader = TableLoader::new();
    loader.append(LoaderCmd::Allocate { file: RSDP_FILE, alignment: 16, zone: 2 });
    loader.append(LoaderCmd::Allocate { file: TABLES_FILE, alignment: 64, zone: 1 });
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: dsdt_csum,
        start: dsdt_offset,
        length: dsdt_len,
    });
    for ptr_offset in [36u32, 40] {
        loader.append(LoaderCmd::AddPtr {
            pointer_file: TABLES_FILE,
            pointee_file: TABLES_FILE,
            pointer_offset: facp_offset + ptr_offset,
            pointer_size: 4,
        });
    }
    loader.append(LoaderCmd::AddPtr {
        pointer_file: TABLES_FILE,
        pointee_file: TABLES_FILE,
        pointer_offset: facp_offset + 140,
        pointer_size: 8,
    });
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: facp_csum,
        start: facp_offset,
        length: facp_len,
    });
    // Non-DSDT/FACP/RSDT secondary tables in their file order, e.g. APIC, HPET,
    // MCFG, WAET. FACS lives in the same blob but has no Checksum slot and is
    // wired to FACP via the FIRMWARE_CTRL pointer above, so skip it here.
    for (sig, off, csum, len) in &list {
        if matches!(sig.as_slice(), b"FACS" | b"DSDT" | b"FACP" | b"RSDT") {
            continue;
        }
        loader.append(LoaderCmd::AddChecksum {
            file: TABLES_FILE,
            result_offset: *csum,
            start: *off,
            length: *len,
        });
    }
    // RSDT lists every non-DSDT table; emit one 4-byte AddPtr per entry slot.
    const RSDT_HEADER_LEN: u32 = 36;
    if rsdt_len < RSDT_HEADER_LEN || (rsdt_len - RSDT_HEADER_LEN) % 4 != 0 {
        bail!("Malformed RSDT length: {rsdt_len}");
    }
    let rsdt_entries = (rsdt_len - RSDT_HEADER_LEN) / 4;
    for i in 0..rsdt_entries {
        loader.append(LoaderCmd::AddPtr {
            pointer_file: TABLES_FILE,
            pointee_file: TABLES_FILE,
            pointer_offset: rsdt_offset + RSDT_HEADER_LEN + i * 4,
            pointer_size: 4,
        });
    }
    loader.append(LoaderCmd::AddChecksum {
        file: TABLES_FILE,
        result_offset: rsdt_csum,
        start: rsdt_offset,
        length: rsdt_len,
    });
    loader.append(LoaderCmd::AddPtr {
        pointer_file: RSDP_FILE,
        pointee_file: TABLES_FILE,
        pointer_offset: 16,
        pointer_size: 4,
    });
    loader.append(LoaderCmd::AddChecksum {
        file: RSDP_FILE,
        result_offset: 8,
        start: 0,
        length: 20,
    });

    if loader.buffer.len() < LDR_LENGTH {
        loader.buffer.resize(LDR_LENGTH, 0);
    }
    Ok(loader.buffer)
}

/// An enum to represent the different QEMU loader commands in a type-safe way.
#[derive(Debug)]
enum LoaderCmd<'a> {
    Allocate {
        file: &'a str,
        alignment: u32,
        zone: u8,
    },
    AddPtr {
        pointer_file: &'a str,
        pointee_file: &'a str,
        pointer_offset: u32,
        pointer_size: u8,
    },
    AddChecksum {
        file: &'a str,
        result_offset: u32,
        start: u32,
        length: u32,
    },
}

/// Builder for QEMU-specific loader commands that instruct firmware how to load and patch ACPI tables.
struct TableLoader {
    /// Buffer containing serialized QEMU loader commands
    buffer: Vec<u8>,
}

impl TableLoader {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(LDR_LENGTH),
        }
    }

    /// Appends a fixed-length, null-padded string to the data buffer.
    fn append_fixed_string(data: &mut Vec<u8>, s: &str) {
        let mut s_bytes = s.as_bytes().to_vec();
        s_bytes.resize(FIXED_STRING_LEN, 0);
        data.extend_from_slice(&s_bytes);
    }

    fn append(&mut self, cmd: LoaderCmd) {
        match cmd {
            LoaderCmd::Allocate {
                file,
                alignment,
                zone,
            } => {
                self.buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, file);
                self.buffer.extend_from_slice(&alignment.to_le_bytes());
                self.buffer.push(zone);
                self.buffer.resize(self.buffer.len() + 63, 0); // Padding
            }
            LoaderCmd::AddPtr {
                pointer_file,
                pointee_file,
                pointer_offset,
                pointer_size,
            } => {
                self.buffer.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, pointer_file);
                Self::append_fixed_string(&mut self.buffer, pointee_file);
                self.buffer.extend_from_slice(&pointer_offset.to_le_bytes());
                self.buffer.push(pointer_size);
                self.buffer.resize(self.buffer.len() + 7, 0); // Padding
            }
            LoaderCmd::AddChecksum {
                file,
                result_offset,
                start,
                length,
            } => {
                self.buffer.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
                Self::append_fixed_string(&mut self.buffer, file);
                self.buffer.extend_from_slice(&result_offset.to_le_bytes());
                self.buffer.extend_from_slice(&start.to_le_bytes());
                self.buffer.extend_from_slice(&length.to_le_bytes());
                self.buffer.resize(self.buffer.len() + 56, 0); // Padding
            }
        }
    }
}

/// Searches for an ACPI table with the given signature and returns its offset,
/// checksum offset, and length.
fn find_acpi_table(tables: &[u8], signature: &str) -> Result<(u32, u32, u32)> {
    if signature.len() != 4 {
        bail!("Signature must be 4 characters long, but got '{signature}'");
    }

    let sig_bytes = signature.as_bytes();

    let mut offset = 0;
    while offset < tables.len() {
        // Ensure there's enough space for a table header
        if offset + 8 > tables.len() {
            bail!("Table not found: {signature}");
        }

        let tbl_sig = &tables[offset..offset + 4];
        let tbl_len_bytes: [u8; 4] = tables[offset + 4..offset + 8].try_into().unwrap();
        let tbl_len = u32::from_le_bytes(tbl_len_bytes) as usize;

        if tbl_sig == sig_bytes {
            // Found the table
            return Ok((offset as u32, (offset + 9) as u32, tbl_len as u32));
        }

        if tbl_len == 0 {
            // Invalid table length, stop searching
            bail!("Found table with zero length at offset {offset}");
        }
        // Move to the next table
        offset += tbl_len;
    }

    bail!("Table not found: {signature}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an 8-byte ACPI table header with the given signature and length.
    /// Body bytes (if any) are caller-appended.
    fn header(sig: &[u8; 4], len: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(sig);
        h.extend_from_slice(&len.to_le_bytes());
        h
    }

    /// Concatenates a list of (sig, padded_body_len) into a blob shaped like
    /// `etc/acpi/tables`. Each entry becomes `<8-byte header><(len-8) zeros>`.
    fn build_blob(tables: &[(&[u8; 4], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(sig, len) in tables {
            out.extend(header(sig, len));
            out.resize(out.len() + (len as usize - 8), 0);
        }
        out
    }

    #[test]
    fn find_acpi_table_returns_offsets_and_csum_for_each_table() {
        // Minimal Canonical-defaults table set, no HPET; 4-entry RSDT (len=36+16).
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 200),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 52),
        ]);

        // Spot-check three tables. csum is the offset of the table's
        // 9th byte (header layout: 4-byte sig, 4-byte length, 1-byte revision,
        // 1-byte checksum -> checksum lives at offset+9).
        let (off, csum, len) = find_acpi_table(&blob, "DSDT").unwrap();
        assert_eq!(off, 64);
        assert_eq!(csum, 73);
        assert_eq!(len, 200);

        let (off, _, len) = find_acpi_table(&blob, "FACP").unwrap();
        assert_eq!(off, 264);
        assert_eq!(len, 244);

        let (off, _, _) = find_acpi_table(&blob, "RSDT").unwrap();
        assert_eq!(off, 64 + 200 + 244 + 144 + 60 + 40); // = 752
    }

    #[test]
    fn list_acpi_tables_walks_blob_and_stops_at_padding() {
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 100),
            (b"FACP", 244),
            (b"RSDT", 40),
        ]);
        let list = list_acpi_tables(&blob).unwrap();
        let sigs: Vec<&[u8]> = list.iter().map(|(s, ..)| s.as_slice()).collect();
        assert_eq!(sigs, [b"FACS".as_slice(), b"DSDT", b"FACP", b"RSDT"]);

        // Padding region (zeros) after the last table must terminate the walk,
        // not be treated as a malformed table.
        let mut blob_padded = blob.clone();
        blob_padded.resize(blob.len() + 4096, 0);
        let list2 = list_acpi_tables(&blob_padded).unwrap();
        assert_eq!(list2.len(), 4);
    }

    /// Decodes one 128-byte QEMU loader command, returning a tuple shaped like
    /// (cmd_type, file_or_ptr_file, optional_pointee_file, payload_u32s).
    /// Used to assert the byte layout of `derive_table_loader` without re-
    /// implementing the encoder.
    fn decode_loader_cmd(cmd: &[u8]) -> (u32, String, Option<String>, Vec<u32>) {
        assert_eq!(cmd.len(), 128);
        let kind = u32::from_le_bytes(cmd[0..4].try_into().unwrap());
        let read_str = |off: usize| -> String {
            let s = &cmd[off..off + FIXED_STRING_LEN];
            let end = s.iter().position(|b| *b == 0).unwrap_or(s.len());
            std::str::from_utf8(&s[..end]).unwrap().to_string()
        };
        match kind {
            // Allocate: file + alignment + zone
            1 => {
                let file = read_str(4);
                let align = u32::from_le_bytes(cmd[60..64].try_into().unwrap());
                let zone = cmd[64] as u32;
                (1, file, None, vec![align, zone])
            }
            // AddPtr: pointer_file + pointee_file + offset + size
            2 => {
                let ptr_file = read_str(4);
                let ptee_file = read_str(60);
                let ptr_off = u32::from_le_bytes(cmd[116..120].try_into().unwrap());
                let ptr_size = cmd[120] as u32;
                (2, ptr_file, Some(ptee_file), vec![ptr_off, ptr_size])
            }
            // AddChecksum: file + result_offset + start + length
            3 => {
                let file = read_str(4);
                let result = u32::from_le_bytes(cmd[60..64].try_into().unwrap());
                let start = u32::from_le_bytes(cmd[64..68].try_into().unwrap());
                let length = u32::from_le_bytes(cmd[68..72].try_into().unwrap());
                (3, file, None, vec![result, start, length])
            }
            other => panic!("unknown loader cmd type {other}"),
        }
    }

    fn split_cmds(loader: &[u8]) -> Vec<&[u8]> {
        assert!(loader.len() >= LDR_LENGTH);
        loader
            .chunks_exact(128)
            .take_while(|chunk| u32::from_le_bytes(chunk[0..4].try_into().unwrap()) != 0)
            .collect()
    }

    #[test]
    fn derive_table_loader_emits_canonical_no_hpet_layout() {
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 100),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 52), // header (36) + 4 × 4-byte entries
        ]);
        let loader = derive_table_loader(&blob).unwrap();
        let cmds: Vec<_> = split_cmds(&loader).into_iter().map(decode_loader_cmd).collect();

        // Expected command sequence per the docstring on derive_table_loader.
        // Allocate rsdp + Allocate tables + AddChecksum DSDT + 3×AddPtr FACP + AddChecksum FACP
        // + AddChecksum APIC + AddChecksum MCFG + AddChecksum WAET + 4×AddPtr RSDT
        // + AddChecksum RSDT + AddPtr RSDP + AddChecksum RSDP = 17 commands.
        assert_eq!(cmds.len(), 17);
        assert_eq!(cmds[0].0, 1); // Allocate
        assert_eq!(cmds[0].1, "etc/acpi/rsdp");
        assert_eq!(cmds[1].0, 1);
        assert_eq!(cmds[1].1, "etc/acpi/tables");
        assert_eq!(cmds[2].0, 3); // AddChecksum DSDT
        assert_eq!(cmds[2].3, vec![64 + 9, 64, 100]);

        // 3 AddPtr at facp+36, facp+40, facp+140 (offsets relative to the
        // FACP base in the concatenated blob)
        let facp_off = 64 + 100;
        for (i, &expected_off) in [36u32, 40, 140].iter().enumerate() {
            let cmd = &cmds[3 + i];
            assert_eq!(cmd.0, 2);
            assert_eq!(cmd.3[0], facp_off + expected_off);
        }
        // 4 RSDT pointers (no HPET) at rsdt+36/+40/+44/+48
        let rsdt_off = 64 + 100 + 244 + 144 + 60 + 40;
        for (i, expected_off) in (36u32..36 + 4 * 4).step_by(4).enumerate() {
            let cmd = &cmds[10 + i];
            assert_eq!(cmd.0, 2);
            assert_eq!(cmd.3[0], rsdt_off + expected_off);
        }
        // RSDT checksum, then the final RSDP wiring + checksum.
        assert_eq!(cmds[14].0, 3); // AddChecksum RSDT
        assert_eq!(cmds[14].1, "etc/acpi/tables");
        assert_eq!(cmds[15].0, 2); // AddPtr rsdp+16 -> tables
        assert_eq!(cmds[15].1, "etc/acpi/rsdp");
        assert_eq!(cmds[15].3, vec![16, 4]);
        assert_eq!(cmds[16].0, 3); // AddChecksum rsdp
        assert_eq!(cmds[16].1, "etc/acpi/rsdp");
        assert_eq!(cmds[16].3, vec![8, 0, 20]);

        // Buffer must be padded to LDR_LENGTH (4096).
        assert_eq!(loader.len(), LDR_LENGTH);
    }

    #[test]
    fn derive_table_loader_with_hpet_adds_an_extra_addchecksum_and_rsdt_ptr() {
        // Same shape with HPET in the mix. RSDT now has 5 entries (FACP, APIC,
        // HPET, MCFG, WAET) so length = 36 + 5*4 = 56. Regression case for the
        // pre-rewrite code that hardcoded 4 RSDT entries.
        let blob = build_blob(&[
            (b"FACS", 64),
            (b"DSDT", 100),
            (b"FACP", 244),
            (b"APIC", 144),
            (b"HPET", 56),
            (b"MCFG", 60),
            (b"WAET", 40),
            (b"RSDT", 56),
        ]);
        let loader = derive_table_loader(&blob).unwrap();
        let cmds: Vec<_> = split_cmds(&loader).into_iter().map(decode_loader_cmd).collect();

        // 17 + 2 commands now: one extra AddChecksum HPET + one extra AddPtr RSDT entry.
        assert_eq!(cmds.len(), 19);
        // Count AddChecksums in `etc/acpi/tables` (i.e. tables blob, not rsdp).
        let checksum_tables: Vec<_> = cmds.iter()
            .filter(|c| c.0 == 3 && c.1 == "etc/acpi/tables")
            .collect();
        // DSDT + FACP + APIC + HPET + MCFG + WAET + RSDT = 7
        assert_eq!(checksum_tables.len(), 7);
        // Count RSDT-entry AddPtrs (5 vs the 4 the old code emitted).
        let rsdt_off = 64 + 100 + 244 + 144 + 56 + 60 + 40;
        let rsdt_ptrs: Vec<_> = cmds.iter()
            .filter(|c| c.0 == 2 && c.1 == "etc/acpi/tables"
                     && c.3[0] >= rsdt_off + 36 && c.3[0] < rsdt_off + 36 + 5 * 4)
            .collect();
        assert_eq!(rsdt_ptrs.len(), 5);
    }
}

