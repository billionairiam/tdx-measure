/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! [`GrubDisk`] backed by an [`ImageSource`]: the GPT and filesystem
//! superblocks are read from the raw disk; files from the partitions.

use super::interp::{GrubDisk, Kind};
use crate::image::{format_guid, guestfish_bin, ImageSource};
use anyhow::{bail, Context, Result};
use log::{debug, warn};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ESP_TYPE: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const SECTOR: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fs {
    module: &'static str,
    uuid: Option<String>,
    label: Option<String>,
}

#[derive(Debug, Clone)]
struct Part {
    num: u32,
    type_guid: String,
    unique_guid: String,
    name: String,
    fs: Option<Fs>,
}

/// The boot disk of an [`ImageSource`] as GRUB sees it.
pub struct ImageDisk {
    parts: Vec<Part>,
    backend: Backend,
}

enum Backend {
    /// Each partition is mounted at `/p<N>` in a guestfish session.
    Guestfish(Guestfish),
    /// Partitions are reached through their mount points in `rootfs`.
    Local {
        rootfs: PathBuf,
        mounts: Vec<(u32, String)>,
    },
}

fn uuid_string(b: &[u8]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn c_string(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let s = String::from_utf8_lossy(&b[..end]).trim_end().to_string();
    (!s.is_empty()).then_some(s)
}

/// Identify the filesystem from the first 4 KiB of a partition.
fn probe_fs(b: &[u8]) -> Option<Fs> {
    if b.len() >= 2048 && b[1024 + 56..1024 + 58] == [0x53, 0xef] {
        return Some(Fs {
            module: "ext2",
            uuid: Some(uuid_string(&b[1024 + 104..1024 + 120])),
            label: c_string(&b[1024 + 120..1024 + 136]),
        });
    }
    if b.starts_with(b"XFSB") {
        return Some(Fs {
            module: "xfs",
            uuid: Some(uuid_string(&b[32..48])),
            label: c_string(&b[108..120]),
        });
    }
    if b.len() >= 512 && b[510..512] == [0x55, 0xaa] {
        let (serial, label) = if &b[82..87] == b"FAT32" {
            (67, 71)
        } else if &b[54..57] == b"FAT" {
            (39, 43)
        } else {
            return None;
        };
        let serial = u32::from_le_bytes(b[serial..serial + 4].try_into().unwrap());
        let label = c_string(&b[label..label + 11]).filter(|l| l != "NO NAME");
        return Some(Fs {
            module: "fat",
            uuid: Some(format!("{:04x}-{:04x}", serial >> 16, serial & 0xffff)),
            label,
        });
    }
    None
}

fn probe_btrfs(b: &[u8]) -> Option<Fs> {
    (b.len() >= 0x12b + 256 && &b[0x40..0x48] == b"_BHRfS_M").then(|| Fs {
        module: "btrfs",
        uuid: Some(uuid_string(&b[0x20..0x30])),
        label: c_string(&b[0x12b..0x12b + 256]),
    })
}

/// Parse the GPT, `read(len, offset)` reading the raw disk.
fn read_partitions(read: &mut dyn FnMut(usize, u64) -> Result<Vec<u8>>) -> Result<Vec<Part>> {
    let header = read(SECTOR as usize, SECTOR)?;
    if header.len() < 92 || &header[0..8] != b"EFI PART" {
        bail!("Invalid GPT signature");
    }
    let lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
    if size < 128 || count > 1024 {
        bail!("Unsupported GPT partition entry layout");
    }
    let len = (count * size).div_ceil(SECTOR as usize) * SECTOR as usize;
    let entries = read(len, lba * SECTOR)?;
    let mut parts = Vec::new();
    for (i, e) in entries.chunks_exact(size).take(count).enumerate() {
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let name: Vec<u16> = e[56..128]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let start = u64::from_le_bytes(e[32..40].try_into().unwrap()) * SECTOR;
        let mut fs = probe_fs(&read(4096, start)?);
        if fs.is_none() {
            fs = probe_btrfs(&read(4096, start + 0x10000).unwrap_or_default());
        }
        parts.push(Part {
            num: i as u32 + 1,
            type_guid: format_guid(&e[0..16]),
            unique_guid: format_guid(&e[16..32]),
            name: String::from_utf16_lossy(&name),
            fs,
        });
    }
    Ok(parts)
}

/// A long-lived `guestfish --listen` session, so the many small reads of a
/// GRUB replay do not each boot the libguestfs appliance.
struct Guestfish {
    bin: String,
    pid: String,
    scratch: PathBuf,
}

impl Guestfish {
    fn start(qcow2: &str) -> Result<Self> {
        let bin = guestfish_bin()?;
        let scratch = std::env::temp_dir().join(format!("tdx_measure_grub_{}", std::process::id()));
        fs_err::create_dir_all(&scratch)?;
        // The forked server keeps inheriting stdout, so it must not be a pipe.
        let out = scratch.join("listen.out");
        let status = Command::new(&bin)
            .args(["--listen", "--ro", "-a", qcow2])
            .stdin(Stdio::null())
            .stdout(fs_err::File::create(&out)?.into_file())
            .stderr(fs_err::File::create(scratch.join("listen.err"))?.into_file())
            .status()
            .context("Failed to start guestfish")?;
        let text = fs_err::read_to_string(&out)?;
        let pid = text
            .split(';')
            .next()
            .and_then(|s| s.trim().strip_prefix("GUESTFISH_PID="))
            .map(str::to_owned);
        let Some(pid) = pid.filter(|_| status.success()) else {
            let err = fs_err::read_to_string(scratch.join("listen.err")).unwrap_or_default();
            let _ = fs_err::remove_dir_all(&scratch);
            bail!("Failed to start guestfish on {qcow2}: {err}");
        };
        let gf = Guestfish { bin, pid, scratch };
        gf.cmd(&["run"])?;
        Ok(gf)
    }

    /// Run one command. Commands that may fail must be prefixed with `-`,
    /// otherwise a failure terminates the server.
    fn cmd(&self, args: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new(&self.bin)
            .arg(format!("--remote={}", self.pid))
            .arg("--")
            .args(args)
            .output()
            .context("Failed to run guestfish")?;
        if !output.status.success() {
            bail!(
                "guestfish {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output.stdout)
    }

    fn is_true(&self, args: &[&str]) -> Result<bool> {
        Ok(String::from_utf8_lossy(&self.cmd(args)?).trim() == "true")
    }

    fn download(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let dest = self.scratch.join("download");
        let _ = fs_err::remove_file(&dest);
        self.cmd(&[
            "-download",
            path,
            dest.to_str().context("non-UTF-8 temp dir")?,
        ])?;
        if !dest.exists() {
            return Ok(None);
        }
        let data = fs_err::read(&dest)?;
        let _ = fs_err::remove_file(&dest);
        Ok(Some(data))
    }
}

impl Drop for Guestfish {
    fn drop(&mut self) {
        let _ = self.cmd(&["exit"]);
        let _ = fs_err::remove_dir_all(&self.scratch);
    }
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// `a` lies strictly below directory `b`.
fn is_under(a: &str, b: &str) -> bool {
    a != b && (b == "/" || a.strip_prefix(b).is_some_and(|r| r.starts_with('/')))
}

enum Mapped {
    Path(String),
    /// The path is where another partition is mounted: an (empty) directory.
    MountPoint,
    /// The path is shadowed by another partition's mount.
    Hidden,
}

/// Map a path on partition `part` to the guest path it is visible at.
fn map_path(mounts: &[(u32, String)], part: u32, path: &str) -> Option<Mapped> {
    let mp = &mounts.iter().find(|(p, _)| *p == part)?.1;
    let guest = match (mp.as_str(), path) {
        (m, "/") => m.to_string(),
        ("/", p) => p.to_string(),
        (m, p) => format!("{m}{p}"),
    };
    for (p2, mp2) in mounts {
        if *p2 != part && is_under(mp2, mp) {
            if guest == *mp2 {
                return Some(Mapped::MountPoint);
            }
            if is_under(&guest, mp2) {
                return Some(Mapped::Hidden);
            }
        }
    }
    Some(Mapped::Path(guest))
}

impl ImageDisk {
    pub fn open(source: &ImageSource) -> Result<Self> {
        match *source {
            ImageSource::Qcow2(qcow2) => {
                let gf = Guestfish::start(qcow2)?;
                let dev = String::from_utf8_lossy(&gf.cmd(&["list-devices"])?)
                    .lines()
                    .next()
                    .context("guestfish found no disk")?
                    .to_string();
                let mut read = |len: usize, off: u64| -> Result<Vec<u8>> {
                    let data =
                        gf.cmd(&["pread-device", &dev, &len.to_string(), &off.to_string()])?;
                    if data.len() != len {
                        bail!("Short read of {len} bytes at {off} from {qcow2}");
                    }
                    Ok(data)
                };
                let parts = read_partitions(&mut read)?;
                for p in parts.iter().filter(|p| p.fs.is_some()) {
                    let mp = format!("/p{}", p.num);
                    gf.cmd(&["mkmountpoint", &mp])?;
                    gf.cmd(&["-mount-ro", &format!("{dev}{}", p.num), &mp])?;
                }
                let mounted = String::from_utf8_lossy(&gf.cmd(&["mountpoints"])?).to_string();
                for p in parts.iter().filter(|p| p.fs.is_some()) {
                    if !mounted
                        .lines()
                        .any(|l| l.ends_with(&format!(": /p{}", p.num)))
                    {
                        warn!("Could not mount partition {} of {qcow2}; GRUB will not find files on it", p.num);
                    }
                }
                Ok(ImageDisk {
                    parts,
                    backend: Backend::Guestfish(gf),
                })
            }
            ImageSource::Local { disk, rootfs } => {
                let parts = read_partitions(&mut |len, off| source.read_disk(len, off))?;
                let fstab =
                    fs_err::read_to_string(Path::new(rootfs).join("etc/fstab")).unwrap_or_default();
                let mounts = local_mounts(&parts, &fstab, disk);
                debug!("grub: partition mounts {mounts:?}");
                Ok(ImageDisk {
                    parts,
                    backend: Backend::Local {
                        rootfs: PathBuf::from(rootfs),
                        mounts,
                    },
                })
            }
        }
    }

    /// The EFI system partition GRUB was started from.
    pub fn esp(&self) -> Option<u32> {
        let mut esps = self.parts.iter().filter(|p| p.type_guid == ESP_TYPE);
        let first = esps.next()?.num;
        if let Backend::Local { mounts, .. } = &self.backend {
            if let Some((n, _)) = mounts.iter().find(|(n, m)| {
                m == "/boot/efi"
                    && self
                        .parts
                        .iter()
                        .any(|p| p.num == *n && p.type_guid == ESP_TYPE)
            }) {
                return Some(*n);
            }
        }
        Some(first)
    }

    fn part(&self, num: u32) -> Option<&Part> {
        self.parts.iter().find(|p| p.num == num)
    }
}

/// Mount points of the partitions according to `/etc/fstab`, with the ESP
/// defaulting to `/boot/efi` and a single remaining filesystem to `/`.
fn local_mounts(parts: &[Part], fstab: &str, disk: &str) -> Vec<(u32, String)> {
    let disk_name = Path::new(disk)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let resolve = |spec: &str| -> Option<u32> {
        let spec = unquote(spec);
        let by = |prefix: &str, dir: &str| {
            spec.strip_prefix(prefix)
                .or_else(|| spec.strip_prefix(dir))
                .map(unquote)
        };
        let find = |f: &dyn Fn(&Part) -> bool| parts.iter().find(|p| f(p)).map(|p| p.num);
        if let Some(v) = by("UUID=", "/dev/disk/by-uuid/") {
            find(&|p| {
                p.fs.as_ref()
                    .and_then(|f| f.uuid.as_deref())
                    .is_some_and(|u| u.eq_ignore_ascii_case(v))
            })
        } else if let Some(v) = by("PARTUUID=", "/dev/disk/by-partuuid/") {
            find(&|p| p.unique_guid.eq_ignore_ascii_case(v))
        } else if let Some(v) = by("LABEL=", "/dev/disk/by-label/") {
            find(&|p| p.fs.as_ref().and_then(|f| f.label.as_deref()) == Some(v))
        } else if let Some(v) = by("PARTLABEL=", "/dev/disk/by-partlabel/") {
            find(&|p| p.name == v)
        } else {
            let rest = spec
                .strip_prefix("/dev/")?
                .strip_prefix(disk_name)
                .filter(|_| !disk_name.is_empty())?;
            let n: u32 = rest.strip_prefix('p').unwrap_or(rest).parse().ok()?;
            find(&|p| p.num == n)
        }
    };
    let mut mounts: Vec<(u32, String)> = Vec::new();
    for line in fstab.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 || fields[0].starts_with('#') || !fields[1].starts_with('/') {
            continue;
        }
        if let Some(n) = resolve(fields[0]) {
            if !mounts.iter().any(|(p, _)| *p == n) {
                let mp = fields[1].trim_end_matches('/');
                mounts.push((n, if mp.is_empty() { "/" } else { mp }.to_string()));
            }
        }
    }
    let mounted = |m: &Vec<(u32, String)>, n: u32| m.iter().any(|(p, _)| *p == n);
    if !mounts.iter().any(|(_, m)| m == "/boot/efi") {
        if let Some(esp) = parts
            .iter()
            .find(|p| p.type_guid == ESP_TYPE && !mounted(&mounts, p.num))
        {
            mounts.push((esp.num, "/boot/efi".into()));
        }
    }
    if !mounts.iter().any(|(_, m)| m == "/") {
        let rest: Vec<u32> = parts
            .iter()
            .filter(|p| p.fs.is_some() && !mounted(&mounts, p.num))
            .map(|p| p.num)
            .collect();
        if let [n] = rest[..] {
            mounts.push((n, "/".into()));
        }
    }
    mounts
}

impl GrubDisk for ImageDisk {
    fn partitions(&mut self) -> Result<Vec<u32>> {
        Ok(self.parts.iter().map(|p| p.num).collect())
    }

    fn fs_module(&mut self, part: u32) -> Result<Option<String>> {
        Ok(self
            .part(part)
            .and_then(|p| p.fs.as_ref())
            .map(|f| f.module.to_string()))
    }

    fn stat(&mut self, part: u32, path: &str) -> Result<Option<Kind>> {
        match &self.backend {
            Backend::Guestfish(gf) => {
                let p = format!("/p{part}{}", path.trim_end_matches('/'));
                if gf.is_true(&["is-file", &p, "followsymlinks:true"])? {
                    Ok(Some(Kind::File))
                } else if gf.is_true(&["is-dir", &p, "followsymlinks:true"])? {
                    Ok(Some(Kind::Dir))
                } else {
                    Ok(None)
                }
            }
            Backend::Local { rootfs, mounts } => Ok(match map_path(mounts, part, path) {
                None | Some(Mapped::Hidden) => None,
                Some(Mapped::MountPoint) => Some(Kind::Dir),
                Some(Mapped::Path(g)) => {
                    match std::fs::metadata(rootfs.join(g.trim_start_matches('/'))) {
                        Ok(m) if m.is_file() => Some(Kind::File),
                        Ok(m) if m.is_dir() => Some(Kind::Dir),
                        _ => None,
                    }
                }
            }),
        }
    }

    fn read(&mut self, part: u32, path: &str) -> Result<Option<Vec<u8>>> {
        if self.stat(part, path)? != Some(Kind::File) {
            return Ok(None);
        }
        match &self.backend {
            Backend::Guestfish(gf) => gf.download(&format!("/p{part}{path}")),
            Backend::Local { rootfs, mounts } => match map_path(mounts, part, path) {
                Some(Mapped::Path(g)) => {
                    Ok(Some(fs_err::read(rootfs.join(g.trim_start_matches('/')))?))
                }
                _ => Ok(None),
            },
        }
    }

    fn fs_uuid(&mut self, part: u32) -> Result<Option<String>> {
        Ok(self
            .part(part)
            .and_then(|p| p.fs.as_ref())
            .and_then(|f| f.uuid.clone()))
    }

    fn fs_label(&mut self, part: u32) -> Result<Option<String>> {
        Ok(self
            .part(part)
            .and_then(|p| p.fs.as_ref())
            .and_then(|f| f.label.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(num: u32, type_guid: &str, unique: &str, uuid: &str) -> Part {
        Part {
            num,
            type_guid: type_guid.into(),
            unique_guid: unique.into(),
            name: String::new(),
            fs: Some(Fs {
                module: "ext2",
                uuid: Some(uuid.into()),
                label: None,
            }),
        }
    }

    #[test]
    fn maps_partitions_to_mount_points() {
        let parts = vec![
            part(
                1,
                ESP_TYPE,
                "AAAA0000-0000-0000-0000-000000000001",
                "1234-abcd",
            ),
            part(
                2,
                "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "AAAA0000-0000-0000-0000-000000000002",
                "3380322c",
            ),
            part(
                3,
                "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "AAAA0000-0000-0000-0000-000000000003",
                "beef",
            ),
        ];
        let fstab = "# comment\nUUID=3380322C / ext4 defaults 0 1\n\
                     PARTUUID=aaaa0000-0000-0000-0000-000000000003 /boot ext4 defaults 0 2\n";
        let mounts = local_mounts(&parts, fstab, "/dev/vda");
        assert_eq!(
            mounts,
            vec![
                (2, "/".into()),
                (3, "/boot".into()),
                (1, "/boot/efi".into())
            ]
        );
        let path = |part, p| match map_path(&mounts, part, p) {
            Some(Mapped::Path(g)) => g,
            Some(Mapped::MountPoint) => "<mountpoint>".into(),
            Some(Mapped::Hidden) | None => "<hidden>".into(),
        };
        assert_eq!(path(3, "/grub/grub.cfg"), "/boot/grub/grub.cfg");
        assert_eq!(path(2, "/boot/grub/grub.cfg"), "<hidden>");
        assert_eq!(path(2, "/boot"), "<mountpoint>");
        assert_eq!(path(3, "/efi/EFI"), "<hidden>");
        assert_eq!(
            path(1, "/EFI/debian/grub.cfg"),
            "/boot/efi/EFI/debian/grub.cfg"
        );
        assert_eq!(path(2, "/"), "/");
        assert_eq!(
            local_mounts(&parts, "/dev/vda3 /boot ext4 0 0", "/dev/vda")[0],
            (3, "/boot".into())
        );
    }

    #[test]
    fn probes_filesystems_like_grub() {
        let mut ext = vec![0u8; 4096];
        ext[1024 + 56..1024 + 58].copy_from_slice(&[0x53, 0xef]);
        ext[1024 + 104..1024 + 120]
            .copy_from_slice(&hex::decode("3380322c4b3911efb6d3525400123456").unwrap());
        ext[1024 + 120..1024 + 124].copy_from_slice(b"root");
        let fs = probe_fs(&ext).unwrap();
        assert_eq!(fs.module, "ext2");
        assert_eq!(
            fs.uuid.as_deref(),
            Some("3380322c-4b39-11ef-b6d3-525400123456")
        );
        assert_eq!(fs.label.as_deref(), Some("root"));

        let mut fat = vec![0u8; 512];
        fat[510..512].copy_from_slice(&[0x55, 0xaa]);
        fat[82..87].copy_from_slice(b"FAT32");
        fat[67..71].copy_from_slice(&0xABCD1234u32.to_le_bytes());
        fat[71..82].copy_from_slice(b"NO NAME    ");
        let fs = probe_fs(&fat).unwrap();
        assert_eq!(
            (fs.module, fs.uuid.as_deref(), fs.label),
            ("fat", Some("abcd-1234"), None)
        );
        assert_eq!(probe_fs(&[0u8; 4096]), None);
    }
}
