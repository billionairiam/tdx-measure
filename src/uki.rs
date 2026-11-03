/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Unified kernel image (UKI) boot: OVMF -> systemd-stub (the UKI) -> Linux.
//!
//! systemd-stub loads the kernel from its `.linux` section with `LoadImage`
//! (measured by firmware into RTMR1), passes the `.cmdline` section as the
//! kernel's `LoadOptions` and serves the `.initrd` section via the
//! `LINUX_INITRD_MEDIA_GUID` device path. The kernel's EFI stub then
//! measures `LoadOptions` and the initrd into RTMR2.
//!
//! This matches systemd-stub before v256; later versions also measure into
//! the TDX RTMRs themselves and add generated cpio archives to the initrd.
//! How the command line is normalized depends on the stub version, which is
//! read from the UKI's `.sdmagic` section.
use crate::image::{extract_gpt_event_data, ImageSource};
use crate::num::read_le;
use crate::util::{authenticode_sha384_hash, debug_print_log, measure_sha384};
use anyhow::{bail, Context, Result};
use log::debug;

/// Where firmware's removable-media boot path finds the UKI.
pub const DEFAULT_UKI_PATH: &str = "/boot/efi/EFI/BOOT/BOOTX64.EFI";

/// The data of PE section `name` as the firmware loads it into memory:
/// `VirtualSize` bytes, zero-filled past `SizeOfRawData`.
pub(crate) fn pe_section(pe: &[u8], name: &str) -> Result<Option<Vec<u8>>> {
    let pe_offset = read_le::<u32>(pe, 0x3c, "PE header offset")? as usize;
    if pe.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        bail!("not a PE image");
    }
    let coff = pe_offset + 4;
    let num_sections = read_le::<u16>(pe, coff + 2, "number of sections")? as usize;
    let optional_header_size = read_le::<u16>(pe, coff + 16, "optional header size")? as usize;
    let table = coff + 20 + optional_header_size;
    for i in 0..num_sections {
        let s = table + i * 40;
        let raw_name = pe.get(s..s + 8).context("section table is truncated")?;
        let len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        if &raw_name[..len] != name.as_bytes() {
            continue;
        }
        let virtual_size = read_le::<u32>(pe, s + 8, "VirtualSize")? as usize;
        let raw_size = read_le::<u32>(pe, s + 16, "SizeOfRawData")? as usize;
        let raw_ptr = read_le::<u32>(pe, s + 20, "PointerToRawData")? as usize;
        let copy = raw_size.min(virtual_size);
        let mut data = pe.get(raw_ptr..raw_ptr + copy)
            .with_context(|| format!("section {name} is truncated"))?
            .to_vec();
        data.resize(virtual_size, 0);
        return Ok(Some(data));
    }
    Ok(None)
}

/// The systemd-stub version from the UKI's `.sdmagic` section
/// (`#### LoaderInfo: systemd-stub 252.39-1~deb12u2 ####`).
pub fn stub_version(image: &[u8]) -> Option<String> {
    let magic = pe_section(image, ".sdmagic").ok()??;
    let magic = String::from_utf8_lossy(&magic);
    let version = magic.split("systemd-stub ").nth(1)?.split_whitespace().next()?;
    Some(version.to_string())
}

/// The major version of a systemd version string such as `252.39-1~deb12u2`.
pub fn stub_major(version: &str) -> Option<u32> {
    version.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// The kernel command line as systemd-stub passes it on (`mangle_stub_cmdline`):
/// decoded as UTF-8 up to the first NUL, with control characters turned into
/// spaces and trailing spaces removed. Since v255 leading whitespace is also
/// removed and DEL counts as whitespace. An unknown version is treated as
/// v255 or newer.
pub fn stub_cmdline(raw: &[u8], stub_major: Option<u32>) -> String {
    let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
    let legacy = stub_major.is_some_and(|v| v < 255);
    let is_space = |c: char| c < ' ' || (!legacy && (c == ' ' || c == '\x7f'));
    let cmdline = String::from_utf8_lossy(raw)
        .chars()
        // Characters outside the BMP are dropped when converting to UTF-16.
        .filter(|c| (*c as u32) <= 0xffff)
        .map(|c| if is_space(c) { ' ' } else { c })
        .collect::<String>();
    let cmdline = cmdline.trim_end_matches(' ');
    if legacy { cmdline } else { cmdline.trim_start_matches(' ') }.to_string()
}

/// The `LoadOptions` systemd-stub hands to the kernel: the UTF-16LE command
/// line including its NUL terminator.
pub fn load_options(cmdline: &str) -> Vec<u8> {
    cmdline.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// Inputs measured for a UKI boot.
pub struct UkiBoot {
    /// The UKI as loaded by firmware.
    pub image: Vec<u8>,
    /// The systemd-stub version, if the UKI has a `.sdmagic` section.
    pub stub_version: Option<String>,
    /// The kernel from `.linux`.
    pub linux: Vec<u8>,
    /// The kernel command line (`cmdline` override or `.cmdline`).
    pub cmdline: Option<String>,
    /// The initrd (`initrd` override or `.initrd`).
    pub initrd: Option<Vec<u8>>,
}

impl UkiBoot {
    pub fn load(
        source: &ImageSource,
        uki_path: &str,
        cmdline: Option<&str>,
        initrd_path: Option<&str>,
    ) -> Result<Self> {
        let image = source.read_file(uki_path)?;
        let section = |name| pe_section(&image, name).with_context(|| format!("Failed to parse {uki_path}"));
        let linux = section(".linux")?
            .with_context(|| format!("{uki_path} has no .linux section; is it a UKI?"))?;
        let stub_version = stub_version(&image);
        let major = stub_version.as_deref().and_then(stub_major);
        let cmdline = match cmdline {
            Some(c) => Some(stub_cmdline(c.as_bytes(), major)),
            None => section(".cmdline")?.map(|c| stub_cmdline(&c, major)),
        };
        let initrd = match initrd_path {
            Some(p) => Some(fs_err::read(p)?),
            None => section(".initrd")?,
        };
        debug!(
            "UKI {uki_path}: systemd-stub {stub_version:?}, {} bytes, .linux {} bytes, initrd {:?} bytes, cmdline {cmdline:?}",
            image.len(), linux.len(), initrd.as_ref().map(Vec::len),
        );
        Ok(Self { image, stub_version, linux, cmdline, initrd })
    }
}

/// RTMR1 and RTMR2 event digests for a UKI boot.
pub(crate) fn rtmr1_rtmr2_logs(
    source: &ImageSource,
    uki: &UkiBoot,
    include_separator: bool,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let gpt = extract_gpt_event_data(source)?;

    // Older TDVF (<202411) moves this separator to RTMR0.
    let mut rtmr1 = vec![measure_sha384(b"Calling EFI Application from Boot Option")];
    if include_separator {
        rtmr1.push(measure_sha384(&[0x00, 0x00, 0x00, 0x00]));
    }
    rtmr1.push(measure_sha384(&gpt));
    rtmr1.push(authenticode_sha384_hash(&uki.image).context("Failed to compute the UKI hash")?);
    rtmr1.push(authenticode_sha384_hash(&uki.linux).context("Failed to compute the .linux hash")?);
    rtmr1.push(measure_sha384(b"Exit Boot Services Invocation"));
    rtmr1.push(measure_sha384(b"Exit Boot Services Returned with Success"));

    // systemd-stub only sets LoadOptions when it has a command line, and only
    // registers the initrd when there is one.
    let mut rtmr2 = Vec::new();
    if let Some(cmdline) = &uki.cmdline {
        rtmr2.push(measure_sha384(&load_options(cmdline)));
    }
    if let Some(initrd) = &uki.initrd {
        rtmr2.push(measure_sha384(initrd));
    }

    debug_print_log("RTMR1", &rtmr1);
    debug_print_log("RTMR2", &rtmr2);
    Ok((rtmr1, rtmr2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE image with the given (name, VirtualSize, raw data) sections.
    fn pe(sections: &[(&str, usize, &[u8])]) -> Vec<u8> {
        let pe_offset = 0x40;
        let table = pe_offset + 24;
        let mut raw_ptr = table + sections.len() * 40;
        let mut img = vec![0u8; raw_ptr];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        img[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        img[pe_offset + 6..pe_offset + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        for (i, (name, vsize, data)) in sections.iter().enumerate() {
            let s = table + i * 40;
            img[s..s + name.len()].copy_from_slice(name.as_bytes());
            img[s + 8..s + 12].copy_from_slice(&(*vsize as u32).to_le_bytes());
            img[s + 16..s + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            img[s + 20..s + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
            raw_ptr += data.len();
        }
        for (_, _, data) in sections {
            img.extend_from_slice(data);
        }
        img
    }

    #[test]
    fn pe_section_uses_virtual_size() {
        let img = pe(&[(".cmdline", 4, b"abcdefgh"), (".initrd", 6, b"xyz")]);
        // Truncated to VirtualSize, and zero-filled past SizeOfRawData.
        assert_eq!(pe_section(&img, ".cmdline").unwrap().unwrap(), b"abcd");
        assert_eq!(pe_section(&img, ".initrd").unwrap().unwrap(), b"xyz\0\0\0");
        assert_eq!(pe_section(&img, ".linux").unwrap(), None);
        assert!(pe_section(b"not a PE image at all, but long enough for e_lfanew", ".linux").is_err());
    }

    #[test]
    fn load_options_match_systemd_stub() {
        let raw = b"  root=/dev/vda1\tro\nquiet\x7f \n\0garbage";
        assert_eq!(stub_cmdline(raw, Some(255)), "root=/dev/vda1 ro quiet");
        assert_eq!(stub_cmdline(raw, None), "root=/dev/vda1 ro quiet");
        // Before v255 leading whitespace is kept and DEL is not whitespace.
        assert_eq!(stub_cmdline(raw, Some(252)), "  root=/dev/vda1 ro quiet\x7f");
        assert_eq!(load_options("ro"), [b'r', 0, b'o', 0, 0, 0]);
    }

    #[test]
    fn stub_version_from_sdmagic() {
        let img = pe(&[(".sdmagic", 52, b"#### LoaderInfo: systemd-stub 252.39-1~deb12u2 ####")]);
        let version = stub_version(&img).unwrap();
        assert_eq!(version, "252.39-1~deb12u2");
        assert_eq!(stub_major(&version), Some(252));
        assert_eq!(stub_version(&pe(&[(".linux", 1, b"x")])), None);
    }
}
