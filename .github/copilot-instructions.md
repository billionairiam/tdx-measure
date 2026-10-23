# Copilot Instructions for tdx-measure

## Project Overview

Rust workspace that pre-calculates Intel TDX guest VM measurement registers (MRTD, RTMR0–2) from image binaries and platform config files. Supports two boot chains: **direct boot** (OVMF → kernel) and **indirect boot** (OVMF → SHIM → Grub → kernel via qcow2).

## Workspace Layout

- **Root crate (`tdx-measure`)** – core measurement library: TDVF parsing, ACPI table parsing/loader derivation, measurement computation. Carries no Docker/process dependencies.
- **`acpi-dump/`** – standalone ACPI-tables dumper library. `acpi_dump::generate_acpi_tables()` builds a patched-QEMU Docker image (from `acpi-dump/Dockerfile.qemu-acpi-dump`) and runs it to dump `etc/acpi/tables` for a given `QemuOptions` shape, without booting the TD. Depends on `tdx-measure` for the `QemuOptions` type; consumed only by the CLI's `gen-acpi`.
- **`cli/`** – CLI binary (`tdx-measure-cli`) wrapping the libraries with clap. Installed via `cargo install --path cli`. Subcommands: `measure` (default when a bare metadata path is given; computes all registers), `gen-acpi` (runs the `acpi-dump` dumper), `gen-metadata` (`cli/src/gen_metadata.rs`, turns a raw QEMU command line into a `metadata.json` skeleton; with `--in-guest` it fills in `measure_config` inside a running TD from the `extract_config_files.py` output and the guest state). `--transcript` (`cli/src/transcript.rs`) produces human-readable dumps (needs `iasl` to disassemble ACPI tables).
- **`qcparser/`** – QEMU command-line parser library (edition 2024). `qcparser::parse()` converts a QEMU invocation string into a structured `Grouped` value; the CLI's `gen-metadata` consumes this to populate `QemuOptions`. `qcparser/command*` are sample inputs.
- **`tests/`** – integration tests. `tests/parse.rs` runs the fast fixture-based golden tests (`tests/fixtures/<name>/metadata.json` + `expected.json`); `tests/regen.rs` holds the slow, `#[ignore]`d Docker/QEMU regeneration tests. `tests/fetch_ovmf.sh` downloads the required `OVMF.fd`.

## Build & Test Commands

```sh
# Build the library
cargo build --release

# Build the CLI
cd cli && cargo build --release

# Run all fast tests (unit + fixture integration)
# Requires OVMF.fd: run ./tests/fetch_ovmf.sh first
./tests/fetch_ovmf.sh
cargo test --release

# Run a single test by name
cargo test --release test_name_here

# Generate a metadata.json skeleton from a raw QEMU command line
cargo run --release -p tdx-measure-cli -- gen-metadata --qemu-command <FILE> --boot-mode <direct|indirect> [-o metadata.json]

# Run slow docker-based regen tests (requires Docker + optionally KVM)
cargo test --release --test regen -- --ignored --nocapture
```

No separate lint or format commands are configured in CI; use `cargo clippy` and `cargo fmt` locally.

## Architecture

### Measurement Flow

1. `MeasureConfig` (deserialized from the `measure_config` block of `metadata.json`) holds the boot mode (`bootmode`: `direct`/`indirect`) + boot-mode-specific input paths; `QemuOptions` (`qemu_options` block) holds the VM shape.
2. `Machine` (built with `bon::Builder`) encapsulates all resolved paths and config needed for measurement.
3. `Machine::measure()` orchestrates:
   - `Tdvf::parse()` → parses OVMF firmware metadata sections
   - `Tdvf::mrtd()` → computes MR TD from firmware image
   - `Tdvf::rtmr0()` → computes RTMR0 from ACPI tables, TD HOB, boot variables, etc.
   - `kernel::*` / `image::*` → compute RTMR1 and RTMR2 depending on boot mode
4. All hashing uses SHA-384 (`sha2` crate).

### ACPI Table Generation

The `gen-acpi` subcommand (backed by the `acpi-dump` crate) builds a Docker image with a patched QEMU that dumps ACPI tables without starting the VM, writing them to the metadata's `acpi_tables_bin` path. `measure` then reads that file back. Distribution-specific QEMU versions are pinned for reproducibility.

### Key Types

- `TdxMeasurements` (`src/lib.rs`) – output struct with `mrtd`, `rtmr0`, `rtmr1`, `rtmr2` as `Vec<u8>`.
- `MeasureConfig` / `QemuOptions` (`src/lib.rs`) – the two top-level `metadata.json` blocks. `bootmode` (`direct`|`indirect`) on `MeasureConfig` selects the boot chain.
- "QEMU shape" – the optional extended fields on `QemuOptions` (`machine`, `devices`, `objects`, …) used by the ACPI dumper, gated by `QemuOptions::has_qemu_shape()`. **Device ordering in the `devices` vec is semantically significant** (affects QEMU PCI auto-slot assignment).
- `Machine` (`src/machine.rs`) – builder-pattern struct that drives the measurement pipeline.

## Key Conventions

- **Error handling**: `anyhow::Result` throughout; `thiserror` for library-specific error types.
- **File I/O**: Always use `fs-err` (`fs_err`) instead of `std::fs` for better error messages.
- **Builder pattern**: `Machine` uses the `bon` crate's `#[derive(bon::Builder)]`.
- **Serialization**: `serde` with `serde-human-bytes` for hex-encoded byte fields.
- **License headers**: All source files carry SPDX Apache-2.0 headers with copyright lines.
- **Test fixtures**: Integration tests auto-discover fixtures by globbing `tests/fixtures/*/metadata.json`. Add new test cases by adding a fixture directory with `metadata.json` + `expected.json`.
- **CI pinning**: GitHub Actions uses full SHA pins for all third-party actions (no `@v4` tags).
