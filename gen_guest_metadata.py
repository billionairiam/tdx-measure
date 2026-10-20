#!/usr/bin/env python3
# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Generate an indirect-boot metadata.json for measuring from inside a running TD.

Run this inside the guest, in the directory where extract_config_files.py wrote
its output. The guest boot disk, kernel cmdline and vCPU count are detected
automatically; memory size and the OVMF.fd path must match the host's QEMU
invocation.
"""
import argparse
import json
import os
import subprocess
import sys

EXTRACTED_FILES = {
    "acpi_tables_bin": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "mok_list": "MokListRT.bin",
    "mok_list_trusted": "MokListTrustedRT.bin",
    "mok_list_x": "MokListXRT.bin",
    "sbat_level": "SbatLevelRT.bin",
}


def detect_boot_disk(esp_mount="/boot/efi"):
    """Return the whole-disk device (e.g. /dev/vda) backing the ESP mount."""
    part = subprocess.run(
        ["findmnt", "-no", "SOURCE", esp_mount],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    name = os.path.basename(part)
    sys_path = os.path.realpath(f"/sys/class/block/{name}")
    if os.path.exists(os.path.join(sys_path, "partition")):
        name = os.path.basename(os.path.dirname(sys_path))
    return f"/dev/{name}"


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-m", "--memory", required=True,
                   help="Guest memory exactly as passed to QEMU -m (e.g. 16G)")
    p.add_argument("--bios", default="OVMF.fd",
                   help="Path to the OVMF.fd used to launch this TD (default: OVMF.fd)")
    p.add_argument("--smp", default=None,
                   help="QEMU -smp value (default: number of online vCPUs)")
    p.add_argument("--tdvf-202411", action="store_true",
                   help="Set if the TDVF/OVMF build is 202411 or newer")
    p.add_argument("--disk", default=None,
                   help="Raw boot disk (default: auto-detect from /boot/efi)")
    p.add_argument("--rootfs", default="/", help="Guest filesystem root (default: /)")
    p.add_argument("-d", "--dir", default=".",
                   help="Directory with extract_config_files.py output (default: .)")
    p.add_argument("-o", "--output", default="metadata.json",
                   help="Output file (default: metadata.json)")
    args = p.parse_args()

    disk = args.disk or detect_boot_disk()
    with open("/proc/cmdline") as f:
        cmdline = f.read().strip()

    measure_config = {
        "bootmode": "indirect",
        "tdvf_before_202411": not args.tdvf_202411,
        "path_boot_xxxx": args.dir,
        "disk": disk,
        "rootfs": args.rootfs,
        "cmdline": cmdline,
    }
    missing = []
    for key, fname in EXTRACTED_FILES.items():
        path = os.path.join(args.dir, fname)
        if not os.path.isfile(path):
            missing.append(path)
        measure_config[key] = path

    meta = {
        "qemu_options": {
            "smp": args.smp or str(os.cpu_count()),
            "memory": args.memory,
            "bios": args.bios,
        },
        "measure_config": measure_config,
    }

    with open(args.output, "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print(json.dumps(meta, indent=2))
    print(f"\nWrote {args.output}")

    if not os.path.isfile(args.bios):
        print(f"Warning: bios {args.bios} not found; copy the host's OVMF.fd here",
              file=sys.stderr)
    if missing:
        print("Warning: missing extracted files (run extract_config_files.py first): "
              + ", ".join(missing), file=sys.stderr)
    if not os.access(disk, os.R_OK):
        print(f"Warning: {disk} is not readable; run tdx-measure as root", file=sys.stderr)


if __name__ == "__main__":
    main()
