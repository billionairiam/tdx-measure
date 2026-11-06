/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Parsing of a signed `grubx64.efi` core image: the `mods` section holds
//! the built-in modules, the embedded config/prefix and an optional memdisk.

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection};
use std::collections::BTreeMap;

const MODS_MAGIC: u32 = 0x676d_696d;
const OBJ_ELF: u32 = 0;
const OBJ_MEMDISK: u32 = 1;
const OBJ_CONFIG: u32 = 2;
const OBJ_PREFIX: u32 = 3;

/// The parts of a GRUB core image that drive its boot flow.
#[derive(Debug, Clone, Default)]
pub struct GrubImage {
    /// Names of the modules linked into the image.
    pub modules: Vec<String>,
    /// Embedded early config, run by the rescue parser (not measured).
    pub config: Option<String>,
    /// Embedded `$prefix`, e.g. `/EFI/debian`.
    pub prefix: Option<String>,
    /// Files of the embedded memdisk, if it could be read.
    pub memdisk: Option<MemFs>,
}

/// An in-memory filesystem (the memdisk). Paths are lower-cased since the
/// supported formats are looked up case-insensitively by GRUB (FAT) or are
/// only ever probed for a few fixed names (tar).
#[derive(Debug, Clone, Default)]
pub struct MemFs {
    files: BTreeMap<String, Vec<u8>>,
    dirs: Vec<String>,
}

impl MemFs {
    fn key(path: &str) -> String {
        let mut out = String::new();
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            out.push('/');
            out.push_str(&part.to_lowercase());
        }
        out
    }

    pub fn insert_file(&mut self, path: &str, data: Vec<u8>) {
        let key = Self::key(path);
        let mut dir = key.as_str();
        while let Some(idx) = dir.rfind('/') {
            dir = &dir[..idx];
            if !dir.is_empty() && !self.dirs.iter().any(|d| d == dir) {
                self.dirs.push(dir.to_string());
            }
        }
        self.files.insert(key, data);
    }

    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(&Self::key(path)).map(Vec::as_slice)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        let key = Self::key(path);
        key.is_empty() || self.dirs.contains(&key)
    }
}

impl GrubImage {
    /// Parse a (signed) `grubx64.efi`.
    pub fn parse(efi: &[u8]) -> Result<Self> {
        let pe = object::File::parse(efi).context("Failed to parse GRUB EFI image")?;
        let mods = pe
            .section_by_name("mods")
            .context("GRUB EFI image has no `mods` section")?
            .data()
            .context("Failed to read GRUB `mods` section")?;
        Self::parse_mods(mods)
    }

    fn parse_mods(mods: &[u8]) -> Result<Self> {
        if mods.len() < 24 || u32_at(mods, 0) != MODS_MAGIC {
            bail!("GRUB `mods` section has a bad magic");
        }
        let offset = u64::from_le_bytes(mods[8..16].try_into().unwrap()) as usize;
        let size = (u64::from_le_bytes(mods[16..24].try_into().unwrap()) as usize).min(mods.len());
        let mut image = GrubImage::default();
        let mut p = offset;
        while p + 8 <= size {
            let ty = u32_at(mods, p);
            let len = u32_at(mods, p + 4) as usize;
            if len < 8 || p + len > size {
                bail!("GRUB module at {p:#x} has a bad size {len:#x}");
            }
            let body = &mods[p + 8..p + len];
            match ty {
                OBJ_ELF => {
                    if let Some(name) = module_name(body)? {
                        image.modules.push(name);
                    }
                }
                OBJ_MEMDISK => {
                    image.memdisk = match read_memdisk(body) {
                        Ok(fs) => Some(fs),
                        Err(e) => {
                            log::warn!("GRUB memdisk is not readable: {e:#}");
                            None
                        }
                    }
                }
                OBJ_CONFIG => image.config = Some(c_string(body)),
                OBJ_PREFIX => image.prefix = Some(c_string(body)),
                _ => {}
            }
            p += len;
        }
        Ok(image)
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

fn c_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn elf_section<'a>(module: &'a [u8], name: &str) -> Result<Option<&'a [u8]>> {
    let elf = object::File::parse(module).context("Failed to parse GRUB module")?;
    match elf.section_by_name(name) {
        Some(s) => Ok(Some(
            s.data().context("Failed to read GRUB module section")?,
        )),
        None => Ok(None),
    }
}

/// The module name from its `.modname` section.
pub fn module_name(module: &[u8]) -> Result<Option<String>> {
    Ok(elf_section(module, ".modname")?.map(c_string))
}

/// The modules a `.mod` file depends on, from its `.moddeps` section.
pub fn module_deps(module: &[u8]) -> Result<Vec<String>> {
    Ok(elf_section(module, ".moddeps")?
        .map(|d| {
            d.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default())
}

fn read_memdisk(data: &[u8]) -> Result<MemFs> {
    if data.len() >= 4 && &data[..4] == b"hsqs" {
        bail!("squashfs memdisks are not supported");
    }
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return read_tar(data);
    }
    if data.len() >= 512 && data[510] == 0x55 && data[511] == 0xaa {
        return read_fat(data);
    }
    bail!("unknown memdisk format")
}

fn read_tar(data: &[u8]) -> Result<MemFs> {
    let mut fs = MemFs::default();
    let mut p = 0;
    while p + 512 <= data.len() {
        let hdr = &data[p..p + 512];
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        let mut name = c_string(&hdr[..100]);
        let prefix = c_string(&hdr[345..500]);
        if &hdr[257..262] == b"ustar" && !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let size_str = c_string(&hdr[124..136]);
        let size = usize::from_str_radix(size_str.trim(), 8)
            .with_context(|| format!("bad tar size {size_str:?}"))?;
        let start = p + 512;
        if start + size > data.len() {
            bail!("truncated tar entry {name}");
        }
        match hdr[156] {
            b'0' | 0 => fs.insert_file(&name, data[start..start + size].to_vec()),
            b'5' => {
                let key = MemFs::key(&name);
                if !fs.dirs.contains(&key) {
                    fs.dirs.push(key);
                }
            }
            _ => {}
        }
        p = start + size.div_ceil(512) * 512;
    }
    Ok(fs)
}

struct Fat<'a> {
    data: &'a [u8],
    cluster_size: usize,
    fat_start: usize,
    data_start: usize,
    bits: u32,
}

impl Fat<'_> {
    fn next(&self, cluster: u32) -> Option<u32> {
        let n = cluster as usize;
        let (val, eoc) = match self.bits {
            12 => {
                let off = self.fat_start + n + n / 2;
                let v = u16_at(self.data, off) as u32;
                (if n & 1 == 1 { v >> 4 } else { v & 0xfff }, 0xff8)
            }
            16 => (u16_at(self.data, self.fat_start + n * 2) as u32, 0xfff8),
            _ => (
                u32_at(self.data, self.fat_start + n * 4) & 0x0fff_ffff,
                0x0fff_fff8,
            ),
        };
        (val >= 2 && val < eoc).then_some(val)
    }

    fn chain(&self, first: u32, limit: Option<usize>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut cluster = Some(first).filter(|&c| c >= 2);
        let mut guard = 0;
        while let Some(c) = cluster {
            let off = self.data_start + (c as usize - 2) * self.cluster_size;
            let chunk = self
                .data
                .get(off..off + self.cluster_size)
                .context("FAT cluster out of range")?;
            out.extend_from_slice(chunk);
            if limit.is_some_and(|l| out.len() >= l) {
                break;
            }
            guard += 1;
            if guard > self.data.len() / self.cluster_size {
                bail!("FAT cluster chain loops");
            }
            cluster = self.next(c);
        }
        if let Some(l) = limit {
            if out.len() < l {
                bail!("FAT file is truncated");
            }
            out.truncate(l);
        }
        Ok(out)
    }

    fn walk(&self, dir: &[u8], path: &str, fs: &mut MemFs, depth: usize) -> Result<()> {
        if depth > 16 {
            bail!("FAT directory nesting too deep");
        }
        let mut lfn: Vec<u16> = Vec::new();
        for e in dir.chunks_exact(32) {
            match e[0] {
                0 => break,
                0xe5 => {
                    lfn.clear();
                    continue;
                }
                _ => {}
            }
            let attr = e[11];
            if attr == 0x0f {
                if e[0] & 0x40 != 0 {
                    lfn.clear();
                }
                let mut part = Vec::with_capacity(13);
                for range in [1..11, 14..26, 28..32] {
                    part.extend(
                        e[range]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])),
                    );
                }
                part.extend(lfn);
                lfn = part;
                continue;
            }
            let name = if lfn.is_empty() {
                let base = String::from_utf8_lossy(&e[..8]).trim_end().to_string();
                let ext = String::from_utf8_lossy(&e[8..11]).trim_end().to_string();
                if ext.is_empty() {
                    base
                } else {
                    format!("{base}.{ext}")
                }
            } else {
                let end = lfn
                    .iter()
                    .position(|&c| c == 0 || c == 0xffff)
                    .unwrap_or(lfn.len());
                String::from_utf16_lossy(&lfn[..end])
            };
            lfn.clear();
            if attr & 0x08 != 0 || name == "." || name == ".." {
                continue;
            }
            let first = ((u16_at(e, 20) as u32) << 16) | u16_at(e, 26) as u32;
            let child = format!("{path}/{name}");
            if attr & 0x10 != 0 {
                fs.dirs.push(MemFs::key(&child));
                let sub = self.chain(first, None)?;
                self.walk(&sub, &child, fs, depth + 1)?;
            } else {
                fs.insert_file(&child, self.chain(first, Some(u32_at(e, 28) as usize))?);
            }
        }
        Ok(())
    }
}

fn read_fat(data: &[u8]) -> Result<MemFs> {
    let bps = u16_at(data, 11) as usize;
    let spc = data[13] as usize;
    let reserved = u16_at(data, 14) as usize;
    let nfats = data[16] as usize;
    let root_entries = u16_at(data, 17) as usize;
    let total = match u16_at(data, 19) {
        0 => u32_at(data, 32) as usize,
        n => n as usize,
    };
    let fat_size = match u16_at(data, 22) {
        0 => u32_at(data, 36) as usize,
        n => n as usize,
    };
    if !bps.is_power_of_two() || bps < 512 || spc == 0 || nfats == 0 || fat_size == 0 {
        bail!("not a FAT filesystem");
    }
    let root_sectors = (root_entries * 32).div_ceil(bps);
    let first_data = reserved + nfats * fat_size + root_sectors;
    let clusters = total.saturating_sub(first_data) / spc;
    let bits = if clusters < 4085 {
        12
    } else if clusters < 65525 {
        16
    } else {
        32
    };
    let fat = Fat {
        data,
        cluster_size: bps * spc,
        fat_start: reserved * bps,
        data_start: first_data * bps,
        bits,
    };
    let root = if bits == 32 {
        fat.chain(u32_at(data, 44), None)?
    } else {
        let start = (reserved + nfats * fat_size) * bps;
        data.get(start..start + root_entries * 32)
            .context("FAT root directory out of range")?
            .to_vec()
    };
    let mut fs = MemFs::default();
    fat.walk(&root, "", &mut fs, 0)?;
    Ok(fs)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a `mods` section body from `(type, payload)` objects.
    pub(crate) fn mods_section(objects: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (ty, payload) in objects {
            let len = 8 + payload.len().div_ceil(4) * 4;
            body.extend_from_slice(&ty.to_le_bytes());
            body.extend_from_slice(&(len as u32).to_le_bytes());
            body.extend_from_slice(payload);
            body.resize(body.len() + (len - 8 - payload.len()), 0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&MODS_MAGIC.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&24u64.to_le_bytes());
        out.extend_from_slice(&((24 + body.len()) as u64).to_le_bytes());
        out.extend(body);
        out
    }

    /// A one-file FAT12 image (`/GRUB.CFG` with a long name `grub.cfg`).
    pub(crate) fn fat12_with(name: &str, content: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 512 * 64];
        img[11..13].copy_from_slice(&512u16.to_le_bytes());
        img[13] = 1;
        img[14..16].copy_from_slice(&1u16.to_le_bytes());
        img[16] = 1;
        img[17..19].copy_from_slice(&16u16.to_le_bytes());
        img[19..21].copy_from_slice(&64u16.to_le_bytes());
        img[22..24].copy_from_slice(&1u16.to_le_bytes());
        img[510] = 0x55;
        img[511] = 0xaa;
        // FAT at sector 1: cluster 2 is end-of-chain.
        img[512..515].copy_from_slice(&[0xf8, 0xff, 0xff]);
        img[515] = 0xff;
        img[516] = 0x0f;
        // Root directory at sector 2 (one sector): LFN entry + short entry.
        let root = 1024;
        let utf16: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let lfn = &mut img[root..root + 32];
        lfn[0] = 0x41;
        lfn[11] = 0x0f;
        let slots = (1..11)
            .step_by(2)
            .chain((14..26).step_by(2))
            .chain((28..32).step_by(2));
        for (i, off) in slots.enumerate() {
            let c = utf16.get(i).copied().unwrap_or(0xffff);
            lfn[off..off + 2].copy_from_slice(&c.to_le_bytes());
        }
        let short = &mut img[root + 32..root + 64];
        short[..11].copy_from_slice(b"GRUB    CFG");
        short[26..28].copy_from_slice(&2u16.to_le_bytes());
        short[28..32].copy_from_slice(&(content.len() as u32).to_le_bytes());
        // Data starts at sector 3 (cluster 2).
        img[1536..1536 + content.len()].copy_from_slice(content);
        img
    }

    #[test]
    fn parses_mods_with_fat_memdisk() {
        let mods = mods_section(&[
            (OBJ_MEMDISK, fat12_with("grub.cfg", b"set a=1\n")),
            (OBJ_CONFIG, b"normal (memdisk)/grub.cfg\n\0".to_vec()),
            (OBJ_PREFIX, b"/EFI/debian\0".to_vec()),
        ]);
        let image = GrubImage::parse_mods(&mods).unwrap();
        assert_eq!(image.config.as_deref(), Some("normal (memdisk)/grub.cfg\n"));
        assert_eq!(image.prefix.as_deref(), Some("/EFI/debian"));
        let memdisk = image.memdisk.unwrap();
        assert_eq!(memdisk.file("/grub.cfg"), Some(&b"set a=1\n"[..]));
        assert_eq!(memdisk.file("/GRUB.CFG"), Some(&b"set a=1\n"[..]));
        assert!(memdisk.is_dir("/"));
    }
}
