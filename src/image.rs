/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::{measure_log, measure_sha384, util::{debug_print_log, authenticode_sha384_hash}};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;
use log::debug;
use crate::util::utf16_encode;

/// Resolve the guestfish binary path via `which`, returning a clear error if
/// it is not installed.
fn guestfish_bin() -> Result<String> {
    let output = Command::new("which")
        .arg("guestfish")
        .output()
        .context("Failed to run `which guestfish`")?;
    if !output.status.success() {
        bail!(
            "guestfish not found. Please install it (e.g. `sudo apt install libguestfs-tools`) and ensure it is on your PATH."
        );
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        bail!(
            "guestfish not found. Please install it (e.g. `sudo apt install libguestfs-tools`) and ensure it is on your PATH."
        );
    }
    Ok(path)
}

/// Helper function to download a file using guestfish
fn guestfish_download(qcow2_path: &str, source_path: &str) -> Result<Vec<u8>> {

    // Create a temporary directory for the extracted files
    let temp_dir = std::env::temp_dir().join("tdx_bootloader_extract");
    std::fs::create_dir_all(&temp_dir)?;

    // Create a temporary file path
    let dest_path = temp_dir.join("extracted_file");

    // Download the file using guestfish
    let output = Command::new(guestfish_bin()?)
        .args(&[
            "--ro", "-a", qcow2_path, "-i",
            "download", source_path, dest_path.to_str().unwrap()
        ])
        .output()
        .context(format!("Failed to extract {}", source_path))?;

    if !output.status.success() {
        bail!("Failed to extract {}: {}", source_path, String::from_utf8_lossy(&output.stderr));
    }

    // Read the extracted file
    let data = std::fs::read(&dest_path)
        .context(format!("Failed to read extracted {}", dest_path.to_str().unwrap()))?;

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(data)
}

/// Helper function to read raw bytes from the disk inside a qcow2 using guestfish
fn guestfish_pread_device(qcow2_path: &str, len: usize, offset: u64) -> Result<Vec<u8>> {
    let output = Command::new(guestfish_bin()?)
        .args(&[
            "--ro", "-a", qcow2_path,
            "run", ":",
            "pread-device", "/dev/sda", &len.to_string(), &offset.to_string()
        ])
        .output()
        .context(format!("Failed to read {} bytes at offset {} from {}", len, offset, qcow2_path))?;

    if !output.status.success() {
        bail!("Failed to read {} bytes at offset {} from {}: {}", len, offset, qcow2_path, String::from_utf8_lossy(&output.stderr));
    }
    Ok(output.stdout)
}

/// Where the guest boot chain (GPT, shim, grub, initrd) is read from.
#[derive(Debug, Clone, Copy)]
pub enum ImageSource<'a> {
    /// A qcow2 disk image on the host, accessed via guestfish.
    Qcow2(&'a str),
    /// The running guest itself: `disk` is the raw boot disk (e.g. `/dev/vda`)
    /// and `rootfs` is the mounted guest filesystem root (e.g. `/`).
    Local { disk: &'a str, rootfs: &'a str },
}

impl ImageSource<'_> {
    /// Read a file from the guest filesystem (absolute guest path).
    fn read_file(&self, guest_path: &str) -> Result<Vec<u8>> {
        match self {
            ImageSource::Qcow2(qcow2) => guestfish_download(qcow2, guest_path),
            ImageSource::Local { rootfs, .. } => {
                let path = Path::new(rootfs).join(guest_path.trim_start_matches('/'));
                fs_err::read(&path).context(format!("Failed to read {}", path.display()))
            }
        }
    }

    /// Read `len` raw bytes at byte `offset` from the boot disk.
    fn read_disk(&self, len: usize, offset: u64) -> Result<Vec<u8>> {
        match self {
            ImageSource::Qcow2(qcow2) => guestfish_pread_device(qcow2, len, offset),
            ImageSource::Local { disk, .. } => {
                use std::io::{Read, Seek, SeekFrom};
                let mut f = fs_err::File::open(disk)?;
                f.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len];
                f.read_exact(&mut buf)
                    .context(format!("Failed to read {} bytes at offset {} from {}", len, offset, disk))?;
                Ok(buf)
            }
        }
    }
}

/// Extracts GPT event data in the format used by EV_EFI_GPT_EVENT
fn extract_gpt_event_data(source: &ImageSource) -> Result<Vec<u8>> {
    // Extract GPT header from LBA 1 (skip MBR at LBA 0)
    let gpt_header = source.read_disk(512, 512).context("Failed to extract GPT header")?;

    // Parse GPT header
    if gpt_header.len() < 92 {
        bail!("GPT header too short");
    }

    // Check GPT signature
    if &gpt_header[0..8] != b"EFI PART" {
        bail!("Invalid GPT signature");
    }

    // Read partition entry info from GPT header
    let partition_entry_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap()) as usize;

    // Calculate how many sectors we need to read for all partition entries
    let entries_size = num_entries * entry_size;
    let sectors_needed = (entries_size + 511) / 512; // Round up to sector boundary

    // Extract partition entries
    let entries_offset = partition_entry_lba * 512;
    let entries_length = sectors_needed * 512;

    let all_entries = source.read_disk(entries_length, entries_offset)
        .context("Failed to extract GPT entries")?;

    // Filter valid partition entries (non-zero PartitionTypeGUID)
    let mut valid_entries = Vec::new();
    for i in 0..num_entries {
        let entry_offset = i * entry_size;
        if entry_offset + entry_size > all_entries.len() {
            break;
        }

        let entry = &all_entries[entry_offset..entry_offset + entry_size];

        // Check if PartitionTypeGUID is non-zero (first 16 bytes)
        let is_valid = !entry[0..16].iter().all(|&b| b == 0);

        if is_valid {
            valid_entries.push(entry.to_vec());
        }
    }

    // Build the EFI_GPT_DATA structure:
    // 1. GPT Header (92 bytes)
    // 2. NumberOfPartitions (8 bytes as UINT64)
    // 3. Valid partition entries (128 bytes each)
    let mut gpt_event_data = Vec::new();

    // Add GPT header (92 bytes)
    gpt_event_data.extend_from_slice(&gpt_header[0..92]);

    // Add NumberOfPartitions as 64-bit value
    let num_valid_partitions = valid_entries.len() as u64;
    gpt_event_data.extend_from_slice(&num_valid_partitions.to_le_bytes());

    // Add valid partition entries
    for entry in valid_entries {
        gpt_event_data.extend_from_slice(&entry);
    }

    Ok(gpt_event_data)
}

/// Reads the data from a file
fn read_file_data(filename: &str) -> Result<Vec<u8>> {
    let path = Path::new(filename);
    if path.exists() {
        match fs::read(path) {
            Ok(data) => {
                Ok(data)
            }
            Err(e) => {
                debug!("Failed to read {}: {}", filename, e);
                // Return empty data if file doesn't exist or can't be read
                Ok(Vec::new())
            }
        }
    } else {
        debug!("File {} not found, using empty data", filename);
        Ok(Vec::new())
    }
}

/// Extracts the kernel version from the command line BOOT_IMAGE parameter
fn extract_kernel_version_from_cmdline(cmdline: &str) -> Result<String> {
    // Look for BOOT_IMAGE parameter
    for param in cmdline.split_whitespace() {
        if param.starts_with("BOOT_IMAGE=") {
            let boot_image = param.strip_prefix("BOOT_IMAGE=").unwrap();
            // Extract version from vmlinuz filename
            // Example: /vmlinuz-6.8.0-60-generic -> 6.8.0-60-generic
            if let Some(version_start) = boot_image.find("vmlinuz-") {
                let version = &boot_image[version_start + 8..]; // Skip "vmlinuz-"
                if !version.is_empty() {
                    return Ok(version.to_string());
                }
            }
        }
    }
    bail!("Could not extract kernel version from command line: {}", cmdline);
}

/// Main function to measure RTMR1 from a guest disk image
pub fn measure_rtmr1_from_image(source: &ImageSource, include_separator: bool) -> Result<Vec<u8>> {

    // Extract bootloader files
    let gpt_data = extract_gpt_event_data(source)?;
    let shim_data = source.read_file("/boot/efi/EFI/ubuntu/shimx64.efi")?;
    let grub_data = source.read_file("/boot/efi/EFI/ubuntu/grubx64.efi")?;

    // Compute hashes of the bootloader components
    let gpt_hash = measure_sha384(&gpt_data);
    let shim_hash = authenticode_sha384_hash(&shim_data).context("Failed to compute shim hash")?;
    let grub_hash = authenticode_sha384_hash(&grub_data).context("Failed to compute grub hash")?;

    // Compute RTMR1 log. Older TDVF (<202411) moves this separator to RTMR0.
    let mut rtmr1_log = vec![
        measure_sha384(b"Calling EFI Application from Boot Option"),
    ];
    if include_separator {
        rtmr1_log.push(measure_sha384(&[0x00, 0x00, 0x00, 0x00])); // Separator
    }
    rtmr1_log.push(gpt_hash);
    rtmr1_log.push(shim_hash);
    rtmr1_log.push(grub_hash);
    rtmr1_log.push(measure_sha384(b"Exit Boot Services Invocation"));
    rtmr1_log.push(measure_sha384(b"Exit Boot Services Returned with Success"));

    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Measures RTMR2 using actual MOK variable data extracted from shim
pub fn measure_rtmr2_from_image(source: &ImageSource, cmdline: &str, ref_mok_list: Option<&str>, ref_mok_list_trusted: Option<&str>, ref_mok_list_x: Option<&str>) -> Result<Vec<u8>> {

    // Extract kernel version from command line and construct initrd path
    let kernel_version = extract_kernel_version_from_cmdline(cmdline)?;
    let initrd_path = format!("/boot/initrd.img-{}", kernel_version);

    // Extract initrd
    let initrd_data = source.read_file(&initrd_path)?;

    // Compute RTMR2 log. MOK variables are optional; skip any that are absent.
    let mut rtmr2_log = Vec::new();
    if let Some(p) = ref_mok_list {
        rtmr2_log.push(measure_sha384(&read_file_data(p)?));
    }
    if let Some(p) = ref_mok_list_x {
        rtmr2_log.push(measure_sha384(&read_file_data(p)?));
    }
    if let Some(p) = ref_mok_list_trusted {
        rtmr2_log.push(measure_sha384(&read_file_data(p)?));
    }
    rtmr2_log.push(measure_sha384(&utf16_encode(cmdline)));
    rtmr2_log.push(measure_sha384(&initrd_data));

    debug_print_log("RTMR2", &rtmr2_log);
    Ok(measure_log(&rtmr2_log))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_source_reads_gpt_and_files() {
        let dir = std::env::temp_dir().join(format!("tdx_measure_local_src_{}", std::process::id()));
        let efi = dir.join("boot/efi/EFI/ubuntu");
        fs_err::create_dir_all(&efi).unwrap();
        fs_err::write(efi.join("shimx64.efi"), b"shim").unwrap();

        // GPT header at LBA 1, 4 x 128-byte entries at LBA 2, entries 0 and 2 valid.
        let mut disk = vec![0u8; 512 * 3];
        disk[512..520].copy_from_slice(b"EFI PART");
        disk[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[512 + 80..512 + 84].copy_from_slice(&4u32.to_le_bytes());
        disk[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        disk[1024] = 0xaa;
        disk[1024 + 256] = 0xbb;
        let disk_path = dir.join("disk.raw");
        fs_err::write(&disk_path, &disk).unwrap();

        let source = ImageSource::Local {
            disk: disk_path.to_str().unwrap(),
            rootfs: dir.to_str().unwrap(),
        };
        assert_eq!(source.read_file("/boot/efi/EFI/ubuntu/shimx64.efi").unwrap(), b"shim");

        let gpt = extract_gpt_event_data(&source).unwrap();
        let _ = fs_err::remove_dir_all(&dir);

        assert_eq!(gpt.len(), 92 + 8 + 2 * 128);
        assert_eq!(&gpt[..92], &disk[512..604]);
        assert_eq!(u64::from_le_bytes(gpt[92..100].try_into().unwrap()), 2);
        assert_eq!(gpt[100], 0xaa);
        assert_eq!(gpt[228], 0xbb);
    }
}
