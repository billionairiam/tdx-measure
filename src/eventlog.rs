/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Parser for the TDX CCEL event log (TCG2 crypto-agile format), used to
//! compare computed events against what the firmware actually measured.
use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::util::measure_log;

pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_EVENT_TAG: u32 = 0x6;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
pub const EV_EFI_GPT_EVENT: u32 = 0x8000_0006;
/// Tagged event id the Linux EFI stub uses when measuring the initrd.
pub const LINUX_INITRD_TAG: u32 = 0x8F3B_22EC;

const TPM_ALG_SHA384: u16 = 0x0C;

#[derive(Debug, Clone)]
pub struct Event {
    /// Entry number; the leading Spec ID event is entry 0.
    pub index: usize,
    /// Byte offset of the entry in the log.
    pub offset: usize,
    /// CC measurement register index: 1 = RTMR0, 2 = RTMR1, 3 = RTMR2.
    pub mr_index: u32,
    pub event_type: u32,
    pub sha384: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

impl Event {
    /// RTMR number this event extends, if any.
    pub fn rtmr(&self) -> Option<usize> {
        if self.event_type == EV_NO_ACTION || self.mr_index == 0 {
            return None;
        }
        Some(self.mr_index as usize - 1)
    }

    /// The tag id of an EV_EVENT_TAG event.
    pub fn tag_id(&self) -> Option<u32> {
        (self.event_type == EV_EVENT_TAG && self.data.len() >= 4)
            .then(|| u32::from_le_bytes(self.data[0..4].try_into().unwrap()))
    }

    /// Event type name plus a short decoding of the event data.
    pub fn describe(&self) -> String {
        let name = event_type_name(self.event_type);
        match self.detail() {
            Some(d) if !d.is_empty() => format!("{name} {d}"),
            _ => name,
        }
    }

    fn detail(&self) -> Option<String> {
        let d = &self.data;
        match self.event_type {
            // UEFI_VARIABLE_DATA: GUID, name length (chars), data length, name
            0x8000_0001 | 0x8000_0002 | 0x8000_00E0 if d.len() >= 32 => {
                let chars = u64::from_le_bytes(d[16..24].try_into().unwrap()) as usize;
                Some(utf16_string(d.get(32..32 + chars * 2)?))
            }
            EV_EVENT_TAG if d.len() >= 8 => {
                let size = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
                Some(ascii_string(d.get(8..8 + size)?))
            }
            // UEFI_IMAGE_LOAD_EVENT: show the file path nodes of the device path
            EV_EFI_BOOT_SERVICES_APPLICATION if d.len() >= 32 => {
                let len = u64::from_le_bytes(d[24..32].try_into().unwrap()) as usize;
                Some(device_path_files(d.get(32..32 + len)?))
            }
            // EV_EFI_PLATFORM_FIRMWARE_BLOB2 / EV_EFI_HANDOFF_TABLES2: u8 length + description
            0x8000_000A | 0x8000_000B if !d.is_empty() => {
                Some(ascii_string(d.get(1..1 + d[0] as usize)?))
            }
            EV_EFI_GPT_EVENT => None,
            _ if d.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b)) && d.iter().any(|&b| b != 0) => {
                let s = ascii_string(d);
                Some(if s.len() > 64 { format!("{}...", &s[..64]) } else { s })
            }
            _ => None,
        }
    }
}

fn event_type_name(t: u32) -> String {
    let name = match t {
        0x1 => "EV_POST_CODE",
        0x3 => "EV_NO_ACTION",
        0x4 => "EV_SEPARATOR",
        0x5 => "EV_ACTION",
        0x6 => "EV_EVENT_TAG",
        0x7 => "EV_S_CRTM_CONTENTS",
        0x8 => "EV_S_CRTM_VERSION",
        0xA => "EV_PLATFORM_CONFIG_FLAGS",
        0xD => "EV_IPL",
        0xE => "EV_IPL_PARTITION_DATA",
        0x8000_0001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x8000_0002 => "EV_EFI_VARIABLE_BOOT",
        0x8000_0003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x8000_0004 => "EV_EFI_BOOT_SERVICES_DRIVER",
        0x8000_0005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x8000_0006 => "EV_EFI_GPT_EVENT",
        0x8000_0007 => "EV_EFI_ACTION",
        0x8000_0008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x8000_0009 => "EV_EFI_HANDOFF_TABLES",
        0x8000_000A => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0x8000_000B => "EV_EFI_HANDOFF_TABLES2",
        0x8000_00E0 => "EV_EFI_VARIABLE_AUTHORITY",
        _ => return format!("type {t:#x}"),
    };
    name.to_string()
}

fn ascii_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches('\0').trim().to_string()
}

fn utf16_string(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// File path (MEDIA_FILEPATH_DP) nodes of a device path, joined with '/'.
fn device_path_files(mut dp: &[u8]) -> String {
    let mut files = Vec::new();
    while dp.len() >= 4 {
        let len = u16::from_le_bytes([dp[2], dp[3]]) as usize;
        if len < 4 || len > dp.len() || (dp[0] == 0x7f && dp[1] == 0xff) {
            break;
        }
        if dp[0] == 0x04 && dp[1] == 0x04 {
            files.push(utf16_string(&dp[4..len]));
        }
        dp = &dp[len..];
    }
    files.join("/")
}

/// Parse a CCEL / TCG2 crypto-agile event log.
pub fn parse_ccel(log: &[u8]) -> Result<Vec<Event>> {
    let u32_at = |o: usize| -> Result<u32> {
        match log.get(o..o + 4) {
            Some(b) => Ok(u32::from_le_bytes(b.try_into().unwrap())),
            None => bail!("event log truncated at offset {o:#x}"),
        }
    };

    // Entry 0: TCG_PCR_EVENT (SHA1 format) carrying the Spec ID Event03 header.
    let spec_size = u32_at(28)? as usize;
    let spec = log.get(32..32 + spec_size)
        .filter(|s| s.len() >= 28 && s.starts_with(b"Spec ID Event03"))
        .ok_or_else(|| anyhow::anyhow!("event log does not start with a Spec ID Event03 header"))?;
    let num_algs = u32::from_le_bytes(spec[24..28].try_into().unwrap()) as usize;
    let mut digest_sizes = HashMap::new();
    for i in 0..num_algs {
        let Some(a) = spec.get(28 + i * 4..32 + i * 4) else {
            bail!("Spec ID event algorithm list is truncated");
        };
        digest_sizes.insert(u16::from_le_bytes([a[0], a[1]]), u16::from_le_bytes([a[2], a[3]]) as usize);
    }
    let mut events = vec![Event {
        index: 0,
        offset: 0,
        mr_index: u32_at(0)?,
        event_type: u32_at(4)?,
        sha384: None,
        data: spec.to_vec(),
    }];

    let mut off = 32 + spec_size;
    while off + 12 <= log.len() {
        let mr_index = u32_at(off)?;
        let event_type = u32_at(off + 4)?;
        // The unused tail of the log area is filled with 0xFF (or zeros).
        if mr_index == u32::MAX || event_type == u32::MAX || (mr_index == 0 && event_type == 0) {
            break;
        }
        let count = u32_at(off + 8)?;
        let mut p = off + 12;
        let mut sha384 = None;
        for _ in 0..count {
            let Some(alg) = log.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]])) else {
                bail!("event log truncated at offset {p:#x}");
            };
            let Some(&size) = digest_sizes.get(&alg) else {
                bail!("unknown digest algorithm {alg:#x} in event at offset {off:#x}");
            };
            let Some(digest) = log.get(p + 2..p + 2 + size) else {
                bail!("event log truncated at offset {p:#x}");
            };
            if alg == TPM_ALG_SHA384 {
                sha384 = Some(digest.to_vec());
            }
            p += 2 + size;
        }
        let size = u32_at(p)? as usize;
        let Some(data) = log.get(p + 4..p + 4 + size) else {
            bail!("event at offset {off:#x} exceeds the log");
        };
        events.push(Event { index: events.len(), offset: off, mr_index, event_type, sha384, data: data.to_vec() });
        off = p + 4 + size;
    }
    Ok(events)
}

/// Replay event digests into a measurement register value.
pub fn replay(digests: &[Vec<u8>]) -> Vec<u8> {
    measure_log(digests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_id_event() -> Vec<u8> {
        let mut spec = b"Spec ID Event03\0".to_vec();
        spec.extend([0u8; 4]); // platform class
        spec.extend([0, 2, 0, 2]); // version, errata, uintn size
        spec.extend(1u32.to_le_bytes());
        spec.extend(TPM_ALG_SHA384.to_le_bytes());
        spec.extend(48u16.to_le_bytes());
        spec.push(0); // vendor info size
        let mut ev = Vec::new();
        ev.extend(0u32.to_le_bytes());
        ev.extend(EV_NO_ACTION.to_le_bytes());
        ev.extend([0u8; 20]);
        ev.extend((spec.len() as u32).to_le_bytes());
        ev.extend(spec);
        ev
    }

    #[test]
    fn parses_events_and_stops_at_padding() {
        let mut log = spec_id_event();
        assert_eq!(log.len(), 0x41);
        // Linux initrd tagged event from a TD event log (RTMR2).
        let entry = hex::decode(concat!(
            "03000000060000000100000", "00c0049b7295074979959f811ba52637911209ec13b37b05f3b56794353be",
            "d1965385dc084db381f7787a77fd9215977298b315000000ec223b8f0d0000004c696e757820696e6974726400"
        )).unwrap();
        log.extend(&entry);
        log.extend([0xff; 64]);

        let events = parse_ccel(&log).unwrap();
        assert_eq!(events.len(), 2);
        let ev = &events[1];
        assert_eq!((ev.index, ev.offset, ev.rtmr()), (1, 0x41, Some(2)));
        assert_eq!(ev.tag_id(), Some(LINUX_INITRD_TAG));
        assert_eq!(ev.describe(), "EV_EVENT_TAG Linux initrd");
        assert_eq!(
            hex::encode(ev.sha384.as_ref().unwrap()),
            "49b7295074979959f811ba52637911209ec13b37b05f3b56794353bed1965385dc084db381f7787a77fd9215977298b3"
        );
    }
}
