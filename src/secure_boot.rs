/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Derives the Secure Boot UEFI variables that TDVF measures into RTMR0
//! (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`, `dbt`) from the firmware image.
//!
//! When OVMF is built with `SECURE_BOOT_ENABLE`, it links `AuthVariableLib`
//! (which creates `SecureBoot`), ships `SecureBootConfigDxe`, and initializes
//! the emulated variable store from the pristine variable store in the CFV.
//! Otherwise `SecureBoot` does not exist and the store starts out empty.

use std::collections::HashSet;

/// FFS file name of `SecurityPkg/VariableAuthenticated/SecureBootConfigDxe`.
const SECURE_BOOT_CONFIG_DXE: [u8; 16] = guid(0xF0E6A44F, 0x7195, 0x41C3, [0xAC, 0x64, 0x54, 0xF2, 0x02, 0xCD, 0x0A, 0x21]);
const LZMA_CUSTOM_DECOMPRESS: [u8; 16] = guid(0xEE4E5898, 0x3914, 0x4259, [0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF]);
const AUTHENTICATED_VARIABLE: [u8; 16] = guid(0xAAF32C78, 0x947B, 0x439A, [0xA1, 0x80, 0x2E, 0x14, 0x4E, 0xC3, 0x77, 0x92]);
const VARIABLE: [u8; 16] = guid(0xDDCF3616, 0x3275, 0x4164, [0x98, 0xB6, 0xFE, 0x85, 0x70, 0x7F, 0xFE, 0x7D]);
pub(crate) const GLOBAL_VARIABLE: [u8; 16] = guid(0x8BE4DF61, 0x93CA, 0x11D2, [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C]);
pub(crate) const IMAGE_SECURITY_DATABASE: [u8; 16] = guid(0xD719B2CB, 0x3D3A, 0x4596, [0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F]);
const SECURE_BOOT_ENABLE_DISABLE: [u8; 16] = guid(0xF0A30BC7, 0xAF08, 0x4556, [0x99, 0xC4, 0x00, 0x10, 0x09, 0xC9, 0x3A, 0x44]);

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]]
}

fn le16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn le24(b: &[u8], off: usize) -> Option<usize> {
    let s = b.get(off..off + 3)?;
    Some(s[0] as usize | (s[1] as usize) << 8 | (s[2] as usize) << 16)
}
fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn le64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// The Secure Boot variables as TDVF measures them; `None` means the variable
/// does not exist (measured with empty data).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct SecureBootVars {
    pub secure_boot: Option<u8>,
    pub pk: Option<Vec<u8>>,
    pub kek: Option<Vec<u8>>,
    pub db: Option<Vec<u8>>,
    pub dbx: Option<Vec<u8>>,
    pub dbt: Option<Vec<u8>>,
}

impl SecureBootVars {
    /// `fw` is the whole firmware image, `cfv` the raw TDVF CFV section.
    pub fn from_firmware(fw: &[u8], cfv: &[u8]) -> Self {
        if !firmware_supports_secure_boot(fw) {
            return Self::default();
        }
        let vars = parse_variable_store(cfv);
        let find = |name: &str, vendor: &[u8; 16]| {
            vars.iter()
                .find(|v| v.name == name && &v.vendor == vendor)
                .map(|v| v.data.clone())
        };
        let pk = find("PK", &GLOBAL_VARIABLE);
        // Mirrors AuthVariableLibInitialize(): Secure Boot is only on in user
        // mode (PK enrolled) and when SecureBootEnable is not explicitly off.
        let user_mode = pk.is_some();
        let enabled = match find("SecureBootEnable", &SECURE_BOOT_ENABLE_DISABLE) {
            Some(d) if user_mode => d.first() == Some(&1),
            _ => user_mode,
        };
        Self {
            secure_boot: Some((user_mode && enabled) as u8),
            pk,
            kek: find("KEK", &GLOBAL_VARIABLE),
            db: find("db", &IMAGE_SECURITY_DATABASE),
            dbx: find("dbx", &IMAGE_SECURITY_DATABASE),
            dbt: find("dbt", &IMAGE_SECURITY_DATABASE),
        }
    }
}

/// Whether the firmware was built with `SECURE_BOOT_ENABLE`, detected by the
/// presence of `SecureBootConfigDxe` in any (possibly LZMA-compressed) FV.
pub(crate) fn firmware_supports_secure_boot(fw: &[u8]) -> bool {
    let mut files = HashSet::new();
    scan_fvs(fw, &mut files, 0);
    files.contains(&SECURE_BOOT_CONFIG_DXE)
}

const MAX_DEPTH: usize = 8;

/// Finds firmware volumes in `buf` and collects the names of all FFS files.
fn scan_fvs(buf: &[u8], files: &mut HashSet<[u8; 16]>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut pos = 40;
    while let Some(i) = buf.get(pos..).and_then(|b| b.windows(4).position(|w| w == b"_FVH")) {
        let base = pos + i - 40;
        let fv_len = le64(buf, base + 32).unwrap_or(0) as usize;
        if fv_len >= 0x48 && fv_len <= buf.len() - base {
            parse_fv(&buf[base..base + fv_len], files, depth);
            pos = base + fv_len + 40;
        } else {
            pos += i + 4;
        }
    }
}

fn parse_fv(fv: &[u8], files: &mut HashSet<[u8; 16]>, depth: usize) {
    let Some(header_len) = le16(fv, 48) else { return };
    let mut off = header_len as usize;
    if let Some(ext) = le16(fv, 52).filter(|&e| e != 0) {
        match le32(fv, ext as usize + 16) {
            Some(ext_size) => off = ext as usize + ext_size as usize,
            None => return,
        }
    }
    loop {
        off = (off + 7) & !7;
        let Some(name) = fv.get(off..off + 16) else { break };
        if name.iter().all(|&b| b == 0xFF) {
            break;
        }
        let (Some(&file_type), Some(&attrs), Some(mut size)) = (fv.get(off + 18), fv.get(off + 19), le24(fv, off + 20)) else { break };
        let mut header = 24;
        if attrs & 0x01 != 0 {
            // FFS_ATTRIB_LARGE_FILE
            let Some(ext) = le64(fv, off + 24) else { break };
            size = ext as usize;
            header = 32;
        }
        if size < header || off + size > fv.len() {
            break;
        }
        files.insert(name.try_into().unwrap());
        // RAW and PAD files carry no sections.
        if file_type != 0x01 && file_type != 0xF0 {
            parse_sections(&fv[off + header..off + size], files, depth);
        }
        off += size;
    }
}

fn parse_sections(buf: &[u8], files: &mut HashSet<[u8; 16]>, depth: usize) {
    let mut off = 0;
    while off + 4 <= buf.len() {
        let (Some(mut size), Some(&sec_type)) = (le24(buf, off), buf.get(off + 3)) else { break };
        let mut header = 4;
        if size == 0xFF_FFFF {
            let Some(ext) = le32(buf, off + 4) else { break };
            size = ext as usize;
            header = 8;
        }
        if size < header || off + size > buf.len() {
            break;
        }
        let section = &buf[off..off + size];
        match sec_type {
            // EFI_SECTION_COMPRESSION, uncompressed payload only
            0x01 if section.get(header + 4) == Some(&0) => {
                parse_sections(&section[header + 5..], files, depth + 1)
            }
            // EFI_SECTION_GUID_DEFINED
            0x02 => {
                let guid = section.get(header..header + 16);
                let data_off = le16(section, header + 16).map(usize::from);
                if let (Some(g), Some(d)) = (guid, data_off) {
                    if g == LZMA_CUSTOM_DECOMPRESS && d <= section.len() {
                        let mut out = Vec::new();
                        if lzma_rs::lzma_decompress(&mut &section[d..], &mut out).is_ok() {
                            parse_sections(&out, files, depth + 1);
                        }
                    }
                }
            }
            // EFI_SECTION_FIRMWARE_VOLUME_IMAGE
            0x17 => scan_fvs(&section[header..], files, depth + 1),
            _ => {}
        }
        off = (off + size + 3) & !3;
    }
}

#[derive(Debug)]
struct Variable {
    name: String,
    vendor: [u8; 16],
    data: Vec<u8>,
}

/// Parses the (authenticated) variable store at the start of the CFV and
/// returns the live variables.
fn parse_variable_store(cfv: &[u8]) -> Vec<Variable> {
    const VAR_ADDED: u8 = 0x3F;
    const VAR_ADDED_IN_DELETED_TRANSITION: u8 = 0x3E;

    let mut store = 0;
    if cfv.get(40..44) == Some(b"_FVH") {
        store = le16(cfv, 48).unwrap_or(0) as usize;
    }
    let header_len = match cfv.get(store..store + 16) {
        Some(g) if g == AUTHENTICATED_VARIABLE => 60,
        Some(g) if g == VARIABLE => 32,
        _ => return Vec::new(),
    };
    let store_end = (store + le32(cfv, store + 16).unwrap_or(0) as usize).min(cfv.len());

    let mut live = Vec::new();
    let mut in_transition = Vec::new();
    let mut off = (store + 28 + 3) & !3;
    while off + header_len <= store_end && le16(cfv, off) == Some(0x55AA) {
        let state = cfv[off + 2];
        let (name_size, data_size) = (
            le32(cfv, off + header_len - 24).unwrap() as usize,
            le32(cfv, off + header_len - 20).unwrap() as usize,
        );
        let vendor: [u8; 16] = cfv[off + header_len - 16..off + header_len].try_into().unwrap();
        let name_off = off + header_len;
        // On x86 the variable data directly follows the name (ALIGNMENT == 1);
        // only variable headers are 4-byte aligned.
        let data_off = name_off + name_size;
        let Some(data) = cfv.get(data_off..data_off + data_size) else { break };
        let name = String::from_utf16_lossy(
            &cfv[name_off..name_off + name_size]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect::<Vec<_>>(),
        );
        let var = Variable { name, vendor, data: data.to_vec() };
        match state {
            VAR_ADDED => live.push(var),
            VAR_ADDED_IN_DELETED_TRANSITION => in_transition.push(var),
            _ => {}
        }
        off = (data_off + data_size + 3) & !3;
    }
    for var in in_transition {
        if !live.iter().any(|v| v.name == var.name && v.vendor == var.vendor) {
            live.push(var);
        }
    }
    live
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fv(files: &[([u8; 16], u8, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, file_type, sections) in files {
            while (0x48 + body.len()) % 8 != 0 {
                body.push(0xFF);
            }
            body.extend_from_slice(name);
            body.extend_from_slice(&[0, 0, *file_type, 0]);
            body.extend_from_slice(&((24 + sections.len()) as u32).to_le_bytes()[..3]);
            body.push(0xF8);
            body.extend_from_slice(sections);
        }
        let mut fv = vec![0u8; 0x48];
        let len = (0x48 + body.len()) as u64;
        fv[32..40].copy_from_slice(&len.to_le_bytes());
        fv[40..44].copy_from_slice(b"_FVH");
        fv[48..50].copy_from_slice(&0x48u16.to_le_bytes());
        fv.extend(body);
        fv
    }

    fn section(sec_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = ((4 + payload.len()) as u32).to_le_bytes()[..3].to_vec();
        s.push(sec_type);
        s.extend_from_slice(payload);
        while s.len() % 4 != 0 {
            s.push(0);
        }
        s
    }

    #[test]
    fn detects_secure_boot_config_dxe_inside_lzma_fv() {
        let inner = fv(&[(SECURE_BOOT_CONFIG_DXE, 0x07, section(0x10, b"PE"))]);
        let mut compressed = Vec::new();
        lzma_rs::lzma_compress(&mut &section(0x17, &inner)[..], &mut compressed).unwrap();
        let mut guided = LZMA_CUSTOM_DECOMPRESS.to_vec();
        guided.extend_from_slice(&24u16.to_le_bytes()); // DataOffset
        guided.extend_from_slice(&1u16.to_le_bytes()); // PROCESSING_REQUIRED
        guided.extend(compressed);
        let outer = fv(&[([0x11; 16], 0x0B, section(0x02, &guided))]);

        let mut fw = vec![0u8; 0x1000];
        fw.extend(&outer);
        assert!(firmware_supports_secure_boot(&fw));

        let plain = fv(&[([0x22; 16], 0x07, section(0x10, b"PE"))]);
        assert!(!firmware_supports_secure_boot(&plain));
    }

    fn auth_var(state: u8, name: &str, vendor: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let name: Vec<u8> = crate::util::utf16_encode(name).into_iter().chain([0, 0]).collect();
        let mut v = vec![0xAA, 0x55, state, 0];
        v.extend([0u8; 4 + 8 + 16 + 4]); // Attributes, MonotonicCount, TimeStamp, PubKeyIndex
        v.extend((name.len() as u32).to_le_bytes());
        v.extend((data.len() as u32).to_le_bytes());
        v.extend(vendor);
        v.extend(&name);
        v.extend(data);
        while v.len() % 4 != 0 {
            v.push(0xFF);
        }
        v
    }

    fn cfv(vars: &[Vec<u8>]) -> Vec<u8> {
        let mut store = AUTHENTICATED_VARIABLE.to_vec();
        let body: Vec<u8> = vars.concat();
        store.extend(((28 + body.len()) as u32).to_le_bytes());
        store.extend([0x5A, 0xFE, 0, 0, 0, 0, 0, 0]);
        store.extend(body);
        let mut cfv = vec![0u8; 0x48];
        cfv[40..44].copy_from_slice(b"_FVH");
        cfv[48..50].copy_from_slice(&0x48u16.to_le_bytes());
        cfv.extend(store);
        cfv.extend([0xFF; 64]);
        cfv
    }

    #[test]
    fn variable_store_yields_live_variables_and_secure_boot_mode() {
        let store = cfv(&[
            auth_var(0x3C, "PK", &GLOBAL_VARIABLE, b"stale"),
            auth_var(0x3F, "PK", &GLOBAL_VARIABLE, b"pk!"),
            auth_var(0x3F, "db", &IMAGE_SECURITY_DATABASE, b"db-data"),
        ]);
        let vars = parse_variable_store(&store);
        let names: Vec<_> = vars.iter().map(|v| (v.name.as_str(), v.data.as_slice())).collect();
        assert_eq!(names, [("PK", &b"pk!"[..]), ("db", &b"db-data"[..])]);

        let fw = fv(&[(SECURE_BOOT_CONFIG_DXE, 0x07, section(0x10, b"PE"))]);
        let sb = SecureBootVars::from_firmware(&fw, &store);
        assert_eq!(sb.secure_boot, Some(1));
        assert_eq!(sb.pk.as_deref(), Some(&b"pk!"[..]));
        assert_eq!(sb.kek, None);

        // No PK: setup mode, Secure Boot off even though SecureBootEnable is set.
        let setup = cfv(&[auth_var(0x3F, "SecureBootEnable", &SECURE_BOOT_ENABLE_DISABLE, &[1])]);
        assert_eq!(SecureBootVars::from_firmware(&fw, &setup).secure_boot, Some(0));

        // Firmware without Secure Boot support: nothing exists.
        let plain = fv(&[([0x22; 16], 0x07, section(0x10, b"PE"))]);
        assert_eq!(SecureBootVars::from_firmware(&plain, &store), SecureBootVars::default());
    }
}
