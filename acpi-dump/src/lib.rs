/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Standalone ACPI-tables dumper: given a QEMU shape ([`QemuOptions`]), builds a
//! patched-QEMU Docker image and runs it to emit the `etc/acpi/tables` blob the
//! guest firmware would have seen, without starting the TD. Kept separate from
//! the measurement core so that crate carries no Docker/process dependencies.

use anyhow::{bail, Context, Result};
use log::{info, warn};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use tdx_measure::QemuOptions;

const DOCKERFILE_QEMU_ACPI_DUMP: &str = include_str!("../Dockerfile.qemu-acpi-dump");
const CONTAINER_NAME: &str = "acpi-tables-generator";
const IMAGE_NAME: &str = "acpi-tables-generator";
const OVMF_IN_CONTAINER: &str = "/usr/share/ovmf/OVMF.fd";


/// Describes how to fetch the QEMU source package for a given distribution.
struct QemuPkg<'a> {
    /// `ppa` -> `pull-ppa-source --ppa ppa:kobuk-team/tdx-release qemu $VERSION`
    /// `main` -> `pull-lp-source qemu $VERSION` (or latest in main when empty)
    source: &'static str,
    /// Version handed to the source fetcher. Empty string == "let the fetcher
    /// pick the current main-archive version" (only meaningful for `main`).
    version: &'a str,
    /// Immutable OCI digest of the base image (`sha256:...`).
    image_digest: &'static str,
}

fn qemu_pkg_for<'a>(distribution: &str, version_override: Option<&'a str>) -> Result<QemuPkg<'a>> {
    // Pinned defaults for reproducibility; override via `--qemu-version`.
    let (source, default_version, image_digest): (&'static str, &'static str, &'static str) = match distribution {
        "ubuntu:24.04" => (
            "ppa",
            "2:8.2.2+ds-0ubuntu1.4+tdx1.1",
            "sha256:023f8a753c22258c9fe2d0005a7d28258038da7d620e9f93e9ad78aa266f9f11",
        ),
        "ubuntu:25.04" => (
            "ppa",
            "1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2",
            "sha256:27771fb7b40a58237c98e8d3e6b9ecdd9289cec69a857fccfb85ff36294dac20",
        ),
        "ubuntu:26.04" => (
            "main",
            "1:10.2.1+ds-1ubuntu4",
            "sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64",
        ),
        other => bail!(
            "Unsupported distribution: {other}. Supported: ubuntu:25.04, ubuntu:26.04"
        ),
    };
    Ok(QemuPkg {
        source,
        version: version_override.unwrap_or(default_version),
        image_digest,
    })
}

/// Builds the QEMU command line that the patched in-container QEMU will run to
/// dump `etc/acpi/tables`. When QEMU shape fields are present in qemu_options
/// (i.e. `machine` is set), the command is taken from those fields plus the
/// seven measurement-related core flags. When no shape is present, falls back
/// to the Canonical direct-boot defaults.
/// The `qom-type` / driver name of an `-object` / `-device` value (the first
/// comma-separated token).
fn head_type(v: &str) -> &str {
    v.split(',').next().unwrap_or("")
}

/// `-object` qom-types that are irrelevant to the ACPI tables and reference
/// host-only resources the dumper container does not have. Dropping them lets
/// QEMU start without changing the guest ACPI:
/// - `tdx-guest`: the dumper is a non-TDX build and never enters a TD.
/// - `secret`: points at a host key file (e.g. LUKS master key); only used to
///   decrypt disk backends, which the ACPI-only dump never reads.
/// - `thread-context`: a NUMA-affinity helper for memory preallocation; has no
///   effect on the guest-visible ACPI (SRAT/SLIT come from `-numa`).
fn is_acpi_irrelevant_object(v: &str) -> bool {
    matches!(head_type(v), "tdx-guest" | "secret" | "thread-context")
}

/// Rewrite an `-object` value for the ACPI dumper, or drop it entirely.
///
/// Returns `None` for objects that must be dropped (see
/// [`is_acpi_irrelevant_object`]). A `memory-backend-file` (typically a host
/// hugepage mount, possibly NUMA-bound and preallocated) is converted to a
/// plain `memory-backend-ram` keeping only `id` and `size` — all the guest
/// SRAT depends on — so the container needs neither the hugepage path nor the
/// host NUMA node, and does not preallocate hundreds of GiB.
fn sanitize_object(v: &str) -> Option<String> {
    if is_acpi_irrelevant_object(v) {
        return None;
    }
    if head_type(v) == "memory-backend-file" {
        let id = prop_value(v, "id").unwrap_or("mem0");
        let size = prop_value(v, "size").unwrap_or("0");
        return Some(format!("memory-backend-ram,id={id},size={size}"));
    }
    Some(v.to_string())
}

/// Self-contained `-chardev` backend types that need no host resource and run
/// unchanged inside the dumper container.
///
/// The classifier is deliberately conservative: only these known-safe types are
/// kept; every other chardev (socket, pty, file, pipe, serial, stdio, vc, …) is
/// treated as host-bound and dropped, along with any `-device` referencing it.
/// This is safe because an ACPI-only dump needs no chardev-backed device — such
/// devices are PCI/ISA endpoints that never appear in the guest ACPI tables.
fn is_self_contained_chardev(v: &str) -> bool {
    matches!(head_type(v), "null" | "ringbuf" | "memory")
}

/// Self-contained `-netdev` backend types that run inside the dumper container
/// without any host resource (slirp `user`, internal `hubport`).
///
/// Conservative by design: only these are kept; every other backend (tap,
/// socket, vhost-*, bridge, vde, dgram, inherited fds, …) is treated as
/// host-bound and dropped.
///
/// Dropping a host-bound netdev does NOT change the guest ACPI. A netdev's
/// backend *type* never appears in the ACPI tables; only whether the NIC that
/// references it occupies its PCI slot does. When we drop e.g. a `vhost-user`
/// netdev, its NIC loses its backend and is rerouted by
/// `device_needs_missing_backend` to a `qemu-xhci` slot placeholder at the same
/// bus/addr, so the slot stays occupied and the tables are unchanged. Empirical
/// proof: `virtio-net-pci` behind a `pcie-root-port` backed by a `user` netdev
/// produces a byte-identical `etc/acpi/tables` blob to a `qemu-xhci` placeholder
/// at the same slot.
///
/// We deliberately do NOT try to keep the real NIC alive by swapping its backend
/// to `user`: production NICs carry params like `tx_queue_size=1024`/`mq=on` that
/// the slirp `user` backend rejects (it caps tx_queue_size at 256), so the dump
/// would fail to start. The placeholder sidesteps every device-specific backend
/// constraint while yielding identical ACPI.
fn is_self_contained_netdev(v: &str) -> bool {
    matches!(head_type(v), "user" | "hubport")
}

/// True if a `-device` value depends on a backend the ACPI dumper cannot
/// satisfy: an inherited fd (`fd=`/`vhostfd=`), or a `chardev=`/`netdev=`
/// reference that is not among the backends still emitted for the dump. These
/// are all PCI/ISA endpoints (disks, NICs, vsock, serial ports) that QEMU
/// discovers at runtime and does not describe in the ACPI tables, so dropping
/// them keeps the tables identical while letting QEMU start.
fn device_needs_missing_backend(
    dev: &str,
    kept_chardevs: &[&str],
    kept_netdevs: &[&str],
) -> bool {
    if dev
        .split(',')
        .any(|t| t.starts_with("vhostfd=") || t.starts_with("fd="))
    {
        return true;
    }
    if let Some(cd) = prop_value(dev, "chardev") {
        if !kept_chardevs.contains(&cd) {
            return true;
        }
    }
    if let Some(nd) = prop_value(dev, "netdev") {
        if !kept_netdevs.contains(&nd) {
            return true;
        }
    }
    false
}

/// Prepare a TD's `-machine` value for the non-TDX ACPI dumper.
///
/// Removes the `confidential-guest-support=...` token (the dumper QEMU is not a
/// real TDX build) and forces `smm=off`. A TDX guest always runs with SMM
/// disabled, so QEMU emits a FADT with `SMI Command Port = 0` and zeroed
/// ACPI enable/disable values. Without `confidential-guest-support`, q35 would
/// default SMM back on and produce a divergent FADT (non-zero SMI command port,
/// ACPI enable/disable bytes), which would not match the tables extracted from
/// inside the real TD. Any pre-existing `smm=...` token is replaced.
fn strip_confidential_guest_support(machine: &str) -> String {
    let mut saw_smm = false;
    let mut out: Vec<String> = machine
        .split(',')
        .filter(|t| !t.starts_with("confidential-guest-support="))
        .map(|t| {
            if t.starts_with("smm=") {
                saw_smm = true;
            }
            t.to_string()
        })
        .collect();
    if !saw_smm {
        out.push("smm=off".to_string());
    }
    out.join(",")
}

/// Extract the value of a comma-separated `key=value` property, if present.
fn prop_value<'a>(spec: &'a str, key: &str) -> Option<&'a str> {
    spec.split(',')
        .find_map(|t| t.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Synthesize dummy `-drive` backends for any `drive=ID` referenced by a device
/// that has no matching `-drive`/`-blockdev`. The ACPI-only dump never reads the
/// disk, but the device must instantiate so the PCI topology (and thus the ACPI
/// tables) matches the reference launch.
fn dummy_drives_for_missing(qo: &QemuOptions) -> Vec<String> {
    let mut defined: Vec<&str> = Vec::new();
    for d in qo.drives.iter() {
        if let Some(id) = prop_value(d, "id") { defined.push(id); }
    }
    for b in qo.blockdevs.iter() {
        if let Some(id) = prop_value(b, "node-name").or_else(|| prop_value(b, "id")) {
            defined.push(id);
        }
    }
    let mut dummies = Vec::new();
    for dev in qo.devices.iter() {
        if let Some(id) = prop_value(dev, "drive") {
            if !defined.contains(&id) && !dummies.iter().any(|s: &String| s.contains(&format!("id={id}"))) {
                dummies.push(format!("if=none,id={id},driver=null-co,read-only=on"));
            }
        }
    }
    dummies
}

/// Backend-free stand-in used to keep a PCI slot occupied when the real device's
/// backend cannot be created in the dumper container. A USB xHCI controller is a
/// plain PCIe endpoint that needs no host resource; empirically its ACPI slot
/// description is byte-identical to any other endpoint at the same address.
const SLOT_PLACEHOLDER_DRIVER: &str = "qemu-xhci";

/// If `dev` is a PCI-slot device (has an explicit `addr=`), return a backend-free
/// placeholder occupying the *same* slot (`bus`/`addr`, preserving
/// `multifunction` and `id`).
///
/// On q35 every `pcie-root-port` is ACPI-hotplug-capable, so QEMU describes each
/// slot in the DSDT differently depending on whether it is *occupied* at build
/// time (`Scope{…}` + hotplug methods) or empty (`Device{_ADR}`). Dropping a
/// device would flip its slot to the empty form and change the DSDT — and thus
/// RTMR0. The slot description depends only on occupancy and address, not on the
/// device type, so a placeholder at the same address reproduces the exact ACPI
/// of a real launch while needing no host backend. Returns `None` for devices
/// without a PCI address (ISA / sub-bus ports), which occupy no hotplug slot.
fn slot_placeholder(dev: &str) -> Option<String> {
    let addr = prop_value(dev, "addr")?;
    let mut p = format!("{SLOT_PLACEHOLDER_DRIVER},addr={addr}");
    if let Some(bus) = prop_value(dev, "bus") {
        p.push_str(&format!(",bus={bus}"));
    }
    if let Some(mf) = prop_value(dev, "multifunction") {
        p.push_str(&format!(",multifunction={mf}"));
    }
    if let Some(id) = prop_value(dev, "id") {
        p.push_str(&format!(",id={id}"));
    }
    Some(p)
}

/// Pick a pseudo-random vsock context id in the valid guest range
/// (`3..=0xFFFF_FFFD`; 0-2 are reserved and `0xFFFF_FFFF` is `VMADDR_CID_ANY`).
///
/// No cryptographic strength is needed — this only has to avoid colliding with a
/// vsock CID already in use on the host, so a time+pid derived value suffices and
/// keeps the crate dependency-free.
fn random_guest_cid() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut x = nanos ^ ((std::process::id() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15;
    // splitmix64 finalizer for a decent spread of the low bits.
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    // Map into 3..=0xFFFF_FFFD.
    3 + (x % (0xFFFF_FFFD - 3 + 1))
}

/// If `dev` carries a `guest-cid=` token, replace its value with a random CID.
///
/// A `vhost-vsock-pci` device kept in the dumper actually opens
/// `/dev/vhost-vsock` and reserves the configured CID; reusing the metadata's
/// fixed CID fails when that CID is already claimed by another VM on the host.
/// The vsock CID does not appear in the ACPI tables, so randomizing it keeps the
/// dump identical while avoiding the collision. Returns `dev` unchanged when no
/// `guest-cid=` token is present.
fn sanitize_guest_cid(dev: &str) -> String {
    if prop_value(dev, "guest-cid").is_none() {
        return dev.to_string();
    }
    let cid = random_guest_cid();
    dev.split(',')
        .map(|t| {
            if t.starts_with("guest-cid=") {
                format!("guest-cid={cid}")
            } else {
                t.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn build_qemu_args(qo: &QemuOptions) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let push = |args: &mut Vec<OsString>, k: &str, v: &str| {
        args.push(k.into());
        args.push(v.into());
    };

    if qo.has_qemu_shape() {
        let machine_val = qo.machine.as_deref().unwrap_or("");
        let machine_val = strip_confidential_guest_support(machine_val);
        push(&mut args, "-accel",     qo.accelerator());
        push(&mut args, "-m",         &qo.memory);
        push(&mut args, "-smp",       &qo.smp_value());
        push(&mut args, "-cpu",       qo.cpu_model());
        args.push("-no-reboot".into());
        args.push("-nodefaults".into());
        push(&mut args, "-vga",       "none");
        args.push("-nographic".into());
        push(&mut args, "-bios",      OVMF_IN_CONTAINER);
        push(&mut args, "-L",         "/usr/share/seabios");
        push(&mut args, "-L",         "/usr/lib/ipxe/qemu");
        push(&mut args, "-machine",   &machine_val);
        for v in &qo.globals    { push(&mut args, "-global", v); }
        for v in &qo.objects    {
            if let Some(obj) = sanitize_object(v) {
                push(&mut args, "-object", &obj);
            }
        }
        for v in &qo.numas      { push(&mut args, "-numa", v); }
        for v in &qo.acpi_tables { push(&mut args, "-acpitable", v); }

        // Net/char backends are kept only if they are self-contained (run in the
        // container without any host resource); every other backend is dropped,
        // along with the endpoint devices that reference it. None of these affect
        // the guest ACPI tables.
        let kept_netdevs: Vec<&str> = qo
            .netdevs
            .iter()
            .filter(|n| is_self_contained_netdev(n))
            .filter_map(|n| prop_value(n, "id"))
            .collect();
        let kept_chardevs: Vec<&str> = qo
            .chardevs
            .iter()
            .filter(|c| is_self_contained_chardev(c))
            .filter_map(|c| prop_value(c, "id"))
            .collect();

        // Devices whose real backend can't be created in the container are not
        // dropped (that would empty their ACPI-hotplug slot and change the DSDT).
        // Instead: PCI-slot devices are replaced by a backend-free placeholder at
        // the same slot; non-slot devices (ISA / virtio-serial ports) are kept as
        // is with a synthesized `null` backend so they stay present.
        let mut synth_null_chardevs: Vec<&str> = Vec::new();
        let mut synth_user_netdevs: Vec<&str> = Vec::new();
        for v in &qo.devices {
            if !device_needs_missing_backend(v, &kept_chardevs, &kept_netdevs) {
                continue;
            }
            if slot_placeholder(v).is_some() {
                continue; // handled by a placeholder; needs no backend
            }
            // Kept-in-place non-slot device: synthesize the missing backend.
            if let Some(cd) = prop_value(v, "chardev") {
                if !kept_chardevs.contains(&cd) && !synth_null_chardevs.contains(&cd) {
                    synth_null_chardevs.push(cd);
                }
            }
            if let Some(nd) = prop_value(v, "netdev") {
                if !kept_netdevs.contains(&nd) && !synth_user_netdevs.contains(&nd) {
                    synth_user_netdevs.push(nd);
                }
            }
        }

        for v in &qo.netdevs {
            if is_self_contained_netdev(v) {
                push(&mut args, "-netdev", v);
            }
        }
        for id in &synth_user_netdevs {
            push(&mut args, "-netdev", &format!("user,id={id}"));
        }
        for v in &qo.chardevs {
            if is_self_contained_chardev(v) {
                push(&mut args, "-chardev", v);
            }
        }
        for id in &synth_null_chardevs {
            push(&mut args, "-chardev", &format!("null,id={id}"));
        }
        for v in &qo.blockdevs  { push(&mut args, "-blockdev", v); }
        for v in &qo.drives     { push(&mut args, "-drive", v); }
        for v in dummy_drives_for_missing(qo) { push(&mut args, "-drive", &v); }
        for v in &qo.devices    {
            if !device_needs_missing_backend(v, &kept_chardevs, &kept_netdevs) {
                push(&mut args, "-device", &sanitize_guest_cid(v));
            } else if let Some(ph) = slot_placeholder(v) {
                push(&mut args, "-device", &ph);
            } else {
                // Non-slot device kept in place with its synthesized backend.
                push(&mut args, "-device", &sanitize_guest_cid(v));
            }
        }
        for v in &qo.fw_cfg     { push(&mut args, "-fw_cfg", v); }
    } else {
        // Canonical direct-boot defaults
        push(&mut args, "-accel",   "kvm");
        push(&mut args, "-m",       &qo.memory);
        push(&mut args, "-smp",     &qo.smp_value());
        push(&mut args, "-cpu",     "host");
        push(&mut args, "-machine", "q35,kernel-irqchip=split,hpet=off,smm=off,pic=off");
        push(&mut args, "-bios",    OVMF_IN_CONTAINER);
        args.push("-nographic".into());
        args.push("-nodefaults".into());
        push(&mut args, "-serial",  "stdio");
    }
    args
}

/// Returns the host's `kvm` group id, if the group exists. Used to grant the
/// container access to `/dev/kvm` and `/dev/vhost-vsock`.
fn kvm_group_id() -> Option<String> {
    let out = Command::new("getent").args(["group", "kvm"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()?
        .lines()
        .next()
        .and_then(|line| line.split(':').nth(2).map(str::to_owned))
}

fn build_docker_image(
    dockerfile_dir: &Path,
    distribution: &str,
    pkg: &QemuPkg,
    acpi_tables: &str,
    acpi_loader: &str,
    acpi_rsdp: &str,
) -> Result<()> {
    info!("Building Docker image: {IMAGE_NAME}");
    match pkg.source {
        "ppa" => info!(
            "QEMU source: ppa:kobuk-team/tdx-release (Intel TDX-patched QEMU {}) on {distribution}",
            pkg.version
        ),
        "main" => info!(
            "QEMU source: {distribution} main archive ({})",
            if pkg.version.is_empty() { "latest" } else { pkg.version }
        ),
        other => info!(
            "QEMU source: {other} ({})",
            if pkg.version.is_empty() { "?" } else { pkg.version }
        ),
    }

    let pinned_image = format!("{distribution}@{}", pkg.image_digest);
    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .args(["--progress", "plain", "--tag", IMAGE_NAME])
        .arg("--build-arg").arg(format!("DISTRIBUTION={pinned_image}"))
        .arg("--build-arg").arg(format!("QEMU_SOURCE={}", pkg.source))
        .arg("--build-arg").arg(format!("QEMU_VERSION={}", pkg.version))
        .arg("--build-arg").arg(format!("ACPI_TABLES={acpi_tables}"))
        .arg("--build-arg").arg(format!("ACPI_LOADER={acpi_loader}"))
        .arg("--build-arg").arg(format!("ACPI_RSDP={acpi_rsdp}"));

    // Forward the host's proxy settings so `apt`/`pull-*-source` work behind a
    // corporate proxy. `http_proxy`/`https_proxy` (and their upper-case forms)
    // are Docker predefined build-args: they need no `ARG` in the Dockerfile and
    // are automatically exported into every `RUN`. Only forwarded when set.
    for var in ["http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                cmd.arg("--build-arg").arg(format!("{var}={val}"));
            }
        }
    }

    let status = cmd
        .arg("--file").arg(dockerfile_dir.join("Dockerfile.qemu-acpi-dump"))
        .arg(dockerfile_dir)
        .status()
        .context("Failed to invoke `docker build`")?;
    if !status.success() {
        bail!("docker build failed (exit {status})");
    }
    Ok(())
}

fn run_docker_container(
    bios: &Path,
    output_dir: &Path,
    qemu_args: &[OsString],
    need_kvm: bool,
    need_vhost_vsock: bool,
) -> Result<()> {
    info!("Running QEMU container to generate ACPI tables...");
    // The Dockerfile skips `subdir('pc-bios')` in QEMU's meson build (the option
    // ROMs aren't needed to dump ACPI tables and adding them ~doubles image size).
    // As a result QEMU prints "rom: file kvmvapic.bin … No such file or directory"
    // (and similar for `linuxboot_dma.bin` if a PCI NIC is in play). Harmless —
    // the ACPI dump runs before any ROM would be loaded.
    warn!(
        "NOTE: harmless ROM-file errors (kvmvapic.bin, linuxboot_dma.bin, ...) from QEMU are expected; \
         pc-bios is skipped in the patched build."
    );

    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--name", CONTAINER_NAME]);

    // The `kvm` group also owns `/dev/vhost-vsock` on Linux, so add it whenever
    // either device matters.
    if let Some(gid) = kvm_group_id() {
        cmd.arg("--group-add").arg(gid);
    }
    if need_kvm {
        if !Path::new("/dev/kvm").exists() {
            bail!(
                "accelerator requires /dev/kvm but the host has none \
                 (use `accel: \"tcg\"` in the qemu block to skip KVM)"
            );
        }
        cmd.args(["--device", "/dev/kvm:/dev/kvm"]);
    }
    if need_vhost_vsock && Path::new("/dev/vhost-vsock").exists() {
        cmd.args(["--device", "/dev/vhost-vsock:/dev/vhost-vsock"]);
    }
    cmd.arg("-v").arg(format!("{}:{OVMF_IN_CONTAINER}:ro", bios.display()));
    cmd.arg("-v").arg(format!("{}:/output", output_dir.display()));
    cmd.arg(IMAGE_NAME);
    cmd.args(qemu_args);

    let status = cmd.status().context("Failed to invoke `docker run`")?;
    if !status.success() {
        bail!("QEMU execution failed (exit {status})");
    }
    Ok(())
}

/// Generate the ACPI tables blob by building and running a patched-QEMU Docker
/// container. The patched QEMU writes the `etc/acpi/tables` blob it would have
/// exposed via fw_cfg to `acpi_tables_bin` and exits before TD entry.
pub fn generate_acpi_tables(
    qemu_options: &QemuOptions,
    acpi_tables_bin: &str,
    acpi_rsdp_bin: &str,
    acpi_loader: &str,
    distribution: &str,
    qemu_version: Option<&str>,
) -> Result<()> {
    let pkg = qemu_pkg_for(distribution, qemu_version)?;

    let bios = Path::new(&qemu_options.bios)
        .canonicalize()
        .with_context(|| format!("BIOS file not found: {}", qemu_options.bios))?;

    let acpi_tables_target = PathBuf::from(acpi_tables_bin);
    let acpi_rsdp_target = PathBuf::from(acpi_rsdp_bin);
    let acpi_loader_target = PathBuf::from(acpi_loader);
    let acpi_tables_dir = acpi_tables_target
        .parent()
        .with_context(|| format!("acpi_tables_bin has no parent dir: {}", acpi_tables_target.display()))?;
    fs_err::create_dir_all(acpi_tables_dir)?;
    let acpi_tables_bin = acpi_tables_target
        .file_name()
        .and_then(OsStr::to_str)
        .context("acpi_tables_bin path must end with a filename")?;
    let acpi_rsdp_bin = acpi_rsdp_target
        .file_name()
        .and_then(OsStr::to_str)
        .context("acpi_rsdp_bin path must end with a filename")?;
    let acpi_loader = acpi_loader_target
        .file_name()
        .and_then(OsStr::to_str)
        .context("acpi_loader path must end with a filename")?;

    info!(
        "ACPI gen config: cpus={}, memory={}, bios={}, target={}",
        qemu_options.smp_value(), qemu_options.memory, bios.display(), acpi_tables_target.display()
    );

    if qemu_options.has_qemu_shape() {
        info!(
            "Using QEMU shape: machine='{}' cpu='{}' accel='{}'",
            qemu_options.machine.as_deref().unwrap_or(""),
            qemu_options.cpu_model(),
            qemu_options.accelerator(),
        );
    }

    // Stage the Dockerfile into a temp build context so `docker build` finds it.
    let build_ctx = tempfile::tempdir().context("Failed to create docker build context")?;
    fs_err::write(
        build_ctx.path().join("Dockerfile.qemu-acpi-dump"),
        DOCKERFILE_QEMU_ACPI_DUMP,
    )?;
    build_docker_image(build_ctx.path(), distribution, &pkg, acpi_tables_bin, acpi_loader, acpi_rsdp_bin)?;

    // Bind-mounted output dir must be writable by the container's non-root `qemu-user`.
    use std::os::unix::fs::PermissionsExt;
    let output_dir = tempfile::tempdir().context("Failed to create ACPI output dir")?;
    fs_err::set_permissions(output_dir.path(), std::fs::Permissions::from_mode(0o777))?;

    let qemu_args = build_qemu_args(qemu_options);
    let need_kvm = if qemu_options.has_qemu_shape() {
        qemu_options.accelerator() == "kvm"
    } else {
        true
    };
    let need_vhost_vsock = qemu_options.has_qemu_shape();

    run_docker_container(&bios, output_dir.path(), &qemu_args, need_kvm, need_vhost_vsock)?;

    // Move the produced ACPI outputs into place; `fs::copy` would inherit the
    // container's restrictive 0600 from the source, so widen to 0644 after.
    for (produced_name, target) in [
        (acpi_tables_bin, &acpi_tables_target),
        (acpi_rsdp_bin, &acpi_rsdp_target),
        (acpi_loader, &acpi_loader_target),
    ] {
        let produced = output_dir.path().join(produced_name);
        if !produced.exists() {
            bail!("ACPI output not found in container output: {}", produced.display());
        }
        if let Some(parent) = target.parent() {
            fs_err::create_dir_all(parent)?;
        }
        fs_err::copy(&produced, target)?;
        fs_err::set_permissions(target, std::fs::Permissions::from_mode(0o644))?;
        info!("ACPI output written to: {}", target.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_pkg_for_known_distros_returns_pinned_defaults() {
        let p = qemu_pkg_for("ubuntu:25.04", None).unwrap();
        assert_eq!(p.source, "ppa");
        assert_eq!(p.version, "1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2");
        assert!(p.image_digest.starts_with("sha256:"));
        assert_eq!(p.image_digest.len(), "sha256:".len() + 64);

        let p = qemu_pkg_for("ubuntu:26.04", None).unwrap();
        assert_eq!(p.source, "main");
        assert_eq!(p.version, "1:10.2.1+ds-1ubuntu4");
        assert!(p.image_digest.starts_with("sha256:"));
        assert_eq!(p.image_digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn qemu_pkg_for_honors_version_override() {
        let p = qemu_pkg_for("ubuntu:26.04", Some("1:10.3.0-1ubuntu1")).unwrap();
        assert_eq!(p.source, "main");
        assert_eq!(p.version, "1:10.3.0-1ubuntu1");

        // Even an empty override (caller asked for "latest") wins over the pin.
        let p = qemu_pkg_for("ubuntu:26.04", Some("")).unwrap();
        assert_eq!(p.version, "");
    }

    #[test]
    fn qemu_pkg_for_rejects_unknown_distro() {
        assert!(qemu_pkg_for("debian:12", None).is_err());
        assert!(qemu_pkg_for("", None).is_err());
    }

    #[test]
    fn build_qemu_args_canonical_fallback_matches_dstack_reference() {
        // Canonical direct-boot args from the upstream `dstack`-derived flow.
        // Pinned because the Canonical-defaults scenario depends on this exact order.
        let qo = QemuOptions {
            memory: "2048M".into(),
            bios: String::new(),
            smp: Some("4".into()),
            machine: None,
            cpu: None,
            accel: None,
            globals: vec![],
            objects: vec![],
            numas: vec![],
            acpi_tables: vec![],
            netdevs: vec![],
            devices: vec![],
            fw_cfg: vec![],
            blockdevs: vec![],
            drives: vec![],
            chardevs: vec![],
        };
        let args = build_qemu_args(&qo);
        let expected: Vec<&str> = vec![
            "-accel", "kvm",
            "-m", "2048M",
            "-smp", "4",
            "-cpu", "host",
            "-machine", "q35,kernel-irqchip=split,hpet=off,smm=off,pic=off",
            "-bios", OVMF_IN_CONTAINER,
            "-nographic",
            "-nodefaults",
            "-serial", "stdio",
        ];
        let got: Vec<&str> = args.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn build_qemu_args_qemu_block_passes_fields_verbatim_and_in_documented_order() {
        let qo = QemuOptions {
            memory: "16384M".into(),
            bios: String::new(),
            smp: Some("8,maxcpus=8".into()),
            machine: Some("q35,kernel_irqchip=split,smm=off,pic=off".into()),
            cpu: Some("Skylake-Server,phys-bits=46".into()),
            accel: Some("tcg".into()),
            globals: vec!["q35-pcihost.pci-hole64-size=4096G".into()],
            objects: vec!["memory-backend-ram,id=mem0,size=16384M".into()],
            numas: vec![],
            acpi_tables: vec![],
            netdevs: vec!["hubport,id=net0,hubid=0".into()],
            chardevs: vec![],
            blockdevs: vec![],
            drives: vec![],
            devices: vec![
                "e1000,netdev=net0,bus=pcie.0,addr=0x2,romfile=".into(),
                "virtio-rng-pci".into(),
            ],
            fw_cfg: vec!["name=opt/ovmf/X-PciMmio64Mb,string=262144".into()],
        };
        let args = build_qemu_args(&qo)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();

        // Core seven flags first (in a documented order), then -machine, then
        // user-supplied lists in documented order.
        assert_eq!(args, vec![
            "-accel", "tcg",
            "-m", "16384M",
            "-smp", "8,maxcpus=8",
            "-cpu", "Skylake-Server,phys-bits=46",
            "-no-reboot",
            "-nodefaults",
            "-vga", "none",
            "-nographic",
            "-bios", OVMF_IN_CONTAINER,
            "-L", "/usr/share/seabios",
            "-L", "/usr/lib/ipxe/qemu",
            "-machine", "q35,kernel_irqchip=split,smm=off,pic=off",
            "-global", "q35-pcihost.pci-hole64-size=4096G",
            "-object", "memory-backend-ram,id=mem0,size=16384M",
            "-netdev", "hubport,id=net0,hubid=0",
            "-device", "e1000,netdev=net0,bus=pcie.0,addr=0x2,romfile=",
            "-device", "virtio-rng-pci",
            "-fw_cfg", "name=opt/ovmf/X-PciMmio64Mb,string=262144",
        ]);
    }

    #[test]
    fn build_qemu_args_strips_tdx_guest_object_and_confidential_guest_support() {
        let qo = QemuOptions {
            memory: "16G".into(),
            bios: String::new(),
            smp: None,
            machine: Some("q35,confidential-guest-support=tdx,hpet=off,memory-backend=ram1".into()),
            cpu: Some("host".into()),
            accel: Some("kvm".into()),
            globals: vec![],
            objects: vec![
                "tdx-guest,id=tdx,sept-ve-disable=true".into(),
                "memory-backend-ram,id=ram1,size=16G".into(),
            ],
            numas: vec![],
            acpi_tables: vec![],
            netdevs: vec![],
            chardevs: vec![],
            blockdevs: vec![],
            drives: vec![],
            devices: vec![],
            fw_cfg: vec![],
        };
        let args = build_qemu_args(&qo)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();

        // tdx-guest object dropped, memory-backend kept.
        assert!(args.iter().all(|a| !a.starts_with("tdx-guest")));
        assert!(args.contains(&"memory-backend-ram,id=ram1,size=16G".to_string()));
        // confidential-guest-support stripped, other machine tokens kept, smm forced off.
        let mi = args.iter().position(|a| a == "-machine").unwrap();
        assert_eq!(args[mi + 1], "q35,hpet=off,memory-backend=ram1,smm=off");
    }

    #[test]
    fn build_qemu_args_synthesizes_dummy_drive_for_missing_reference() {
        let qo = QemuOptions {
            memory: "2G".into(),
            bios: String::new(),
            smp: None,
            machine: Some("q35".into()),
            cpu: Some("host".into()),
            accel: Some("kvm".into()),
            globals: vec![],
            objects: vec![],
            numas: vec![],
            acpi_tables: vec![],
            netdevs: vec![],
            chardevs: vec![],
            blockdevs: vec![],
            drives: vec![],
            devices: vec!["virtio-blk-pci,drive=virtio-disk0".into()],
            fw_cfg: vec![],
        };
        let args = build_qemu_args(&qo)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();
        assert!(args.contains(&"if=none,id=virtio-disk0,driver=null-co,read-only=on".to_string()));
    }

    #[test]
    fn build_qemu_args_sanitizes_host_backends_but_keeps_acpi_shape() {
        let qo = QemuOptions {
            memory: "196608".into(),
            bios: String::new(),
            smp: None,
            machine: Some("q35,confidential-guest-support=lsec0,hpet=off".into()),
            cpu: Some("host".into()),
            accel: Some("kvm".into()),
            globals: vec![],
            objects: vec![
                "secret,file=/var/lib/libvirt/qemu/master-key.aes,format=raw,id=masterKey0".into(),
                "iothread,id=iothread1".into(),
                "thread-context,id=tc-ram-node0,node-affinity=1".into(),
                "memory-backend-file,host-nodes=1,id=ram-node0,mem-path=/dev/hugepages/x,policy=bind,prealloc=true,prealloc-context=tc-ram-node0,reserve=true,share=true,size=206158430208".into(),
                "tdx-guest,id=lsec0".into(),
            ],
            numas: vec!["node,cpus=0-1,memdev=ram-node0,nodeid=0".into()],
            acpi_tables: vec![],
            netdevs: vec![
                "vhost-user,chardev=charnet0,id=hostnet0".into(),
                "user,id=usernet0".into(),
            ],
            chardevs: vec![
                "socket,id=charnet0,path=/var/run/openvswitch/x,server=on".into(),
                "socket,fd=41,id=charchannel0,server=on".into(),
                "pty,id=charserial0,logfile=/dev/fdset/0".into(),
                // A host-bound type not matched by any fd=/path= heuristic:
                // still dropped because it isn't on the self-contained whitelist.
                "pipe,id=charpipe0,path=/tmp/p".into(),
                // Self-contained: kept.
                "null,id=charnull0".into(),
            ],
            blockdevs: vec![],
            drives: vec![],
            devices: vec![
                "pcie-root-port,addr=0x1,bus=pcie.0,chassis=1,id=pci.1,port=1".into(),
                "virtio-scsi-pci,addr=0x1,bus=pci.2,id=scsi0,iothread=iothread1".into(),
                "vhost-user-blk-pci,addr=0x1,bus=pci.4,chardev=chr-vu-disk0,id=disk0".into(),
                "virtio-net-pci,addr=0x2,bus=pci.6,id=net0,netdev=hostnet0".into(),
                "isa-serial,chardev=charserial0,id=serial0".into(),
                "isa-debugcon,chardev=charpipe0,id=debug0".into(),
                "vhost-vsock-pci,addr=0x1b,bus=pcie.0,guest-cid=4,id=vsock0,vhostfd=39".into(),
                "pvpanic,ioport=1285".into(),
            ],
            fw_cfg: vec![],
        };
        let args = build_qemu_args(&qo)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();
        let has = |v: &str| args.iter().any(|a| a == v);

        // Host-only / TDX objects dropped; hugepage backend converted to plain RAM.
        assert!(args.iter().all(|a| !a.starts_with("secret,")));
        assert!(args.iter().all(|a| !a.starts_with("thread-context,")));
        assert!(args.iter().all(|a| !a.starts_with("tdx-guest,")));
        assert!(args.iter().all(|a| !a.starts_with("memory-backend-file,")));
        assert!(has("memory-backend-ram,id=ram-node0,size=206158430208"));
        assert!(has("iothread,id=iothread1"));

        // Host-bound netdev/chardevs dropped; self-contained ones kept.
        assert!(args.iter().all(|a| !a.starts_with("vhost-user,")));
        assert!(has("user,id=usernet0"));
        assert!(args.iter().all(|a| !a.contains("path=/var/run/openvswitch")));
        assert!(args.iter().all(|a| !a.starts_with("pty,")));
        // Host-bound type with no fd=/path= heuristic is still dropped by the
        // whitelist; self-contained `null` chardev is kept.
        assert!(args.iter().all(|a| !a.starts_with("pipe,")));
        assert!(has("null,id=charnull0"));

        // ACPI-shaping devices kept as-is.
        assert!(has("pcie-root-port,addr=0x1,bus=pcie.0,chassis=1,id=pci.1,port=1"));
        assert!(has("virtio-scsi-pci,addr=0x1,bus=pci.2,id=scsi0,iothread=iothread1"));
        assert!(has("pvpanic,ioport=1285"));

        // PCI-slot devices with unsatisfiable backends are replaced by a
        // placeholder at the SAME slot (bus/addr) so the ACPI hotplug slot stays
        // occupied — the original device types are gone.
        assert!(args.iter().all(|a| !a.starts_with("vhost-user-blk-pci,")));
        assert!(args.iter().all(|a| !a.starts_with("virtio-net-pci,")));
        assert!(args.iter().all(|a| !a.starts_with("vhost-vsock-pci,")));
        assert!(has("qemu-xhci,addr=0x1,bus=pci.4,id=disk0"));
        assert!(has("qemu-xhci,addr=0x2,bus=pci.6,id=net0"));
        assert!(has("qemu-xhci,addr=0x1b,bus=pcie.0,id=vsock0"));

        // Non-slot devices (ISA / debugcon) are kept in place with a synthesized
        // `null` backend so they remain present.
        assert!(has("isa-serial,chardev=charserial0,id=serial0"));
        assert!(has("isa-debugcon,chardev=charpipe0,id=debug0"));
        assert!(has("null,id=charserial0"));
        assert!(has("null,id=charpipe0"));

        // NUMA topology preserved (drives SRAT).
        assert!(has("node,cpus=0-1,memdev=ram-node0,nodeid=0"));
    }

    #[test]
    fn sanitize_guest_cid_randomizes_only_the_cid_token() {
        let dev = "vhost-vsock-pci,addr=0x1b,bus=pcie.0,guest-cid=4,id=vsock0";
        let out = sanitize_guest_cid(dev);
        // Same token order/count, only the guest-cid value changed.
        assert_eq!(dev.split(',').count(), out.split(',').count());
        assert!(out.contains("vhost-vsock-pci"));
        assert!(out.contains("addr=0x1b"));
        assert!(out.contains("bus=pcie.0"));
        assert!(out.contains("id=vsock0"));
        assert!(!out.contains("guest-cid=4"));
        let cid: u64 = prop_value(&out, "guest-cid").unwrap().parse().unwrap();
        assert!((3..=0xFFFF_FFFD).contains(&cid));
    }

    #[test]
    fn sanitize_guest_cid_leaves_devices_without_cid_untouched() {
        let dev = "pvpanic,ioport=1285";
        assert_eq!(sanitize_guest_cid(dev), dev);
    }

    #[test]
    fn build_qemu_args_randomizes_guest_cid_for_passthrough_vsock() {
        let qo = QemuOptions {
            memory: "2G".into(),
            bios: String::new(),
            smp: None,
            machine: Some("q35".into()),
            cpu: None,
            accel: None,
            globals: vec![],
            objects: vec![],
            numas: vec![],
            acpi_tables: vec![],
            netdevs: vec![],
            chardevs: vec![],
            blockdevs: vec![],
            drives: vec![],
            // A vhost-vsock-pci without an inherited fd and without a PCI addr is
            // kept verbatim (no placeholder), so its guest-cid must be randomized.
            devices: vec!["vhost-vsock-pci,guest-cid=99,id=vsock0".into()],
            fw_cfg: vec![],
        };

        let args = build_qemu_args(&qo)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect::<Vec<_>>();

        // The vsock device is still present but no longer carries the fixed CID.
        let dev = args
            .iter()
            .find(|a| a.starts_with("vhost-vsock-pci,"))
            .expect("vsock device kept");
        assert!(!dev.contains("guest-cid=99"));
        let cid: u64 = prop_value(dev, "guest-cid").unwrap().parse().unwrap();
        assert!((3..=0xFFFF_FFFD).contains(&cid));
    }
}
