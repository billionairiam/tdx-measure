/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Prediction of what a GRUB 2 EFI image measures into RTMR2 when GRUB's
//! TPM/CC verifier measures every command and file (as e.g. veLinux and
//! Debian builds do).

mod disk;
mod efi;
mod interp;
mod script;

pub use disk::ImageDisk;
pub use efi::{GrubImage, MemFs};
pub use interp::{simulate, GrubBoot, GrubDisk, GrubEvent, Kind};
