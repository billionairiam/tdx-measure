/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * Copyright (c) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use tdx_measure::Machine;
use fs_err as fs;
use std::path::{Path, PathBuf};

mod transcript;
mod gen_metadata;
use transcript::generate_transcript;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Measurement arguments used when no subcommand is given
    /// (bare `tdx-measure <metadata.json>` is an alias for `measure`).
    #[command(flatten)]
    measure: MeasureArgs,
}

/// Arguments for computing TDX measurements from a metadata.json.
#[derive(Args, Default)]
struct MeasureArgs {
    /// Path to metadata json file
    metadata: Option<PathBuf>,

    /// Output JSON
    #[arg(long)]
    json: bool,

    /// Output JSON to file
    #[arg(long)]
    json_file: Option<PathBuf>,

    /// Generate a human-readable transcript of all metadata files and write to the specified file
    #[arg(long)]
    transcript: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a metadata.json from a raw QEMU command line.
    GenMetadata {
        /// Path to a file containing the QEMU command line.
        #[arg(long)]
        qemu_command: PathBuf,
        /// Boot mode for the generated metadata.
        #[arg(long, value_parser = ["direct", "indirect"])]
        boot_mode: String,
        /// Mark the TDVF firmware as the 202411 build or newer (omits the trailing RTMR0 separator).
        #[arg(long)]
        tdvf_after_202411: bool,
        /// Path to write the generated metadata.json.
        #[arg(short, long, default_value = "metadata.json")]
        output: PathBuf,
    },

    /// Generate ACPI tables with QEMU for the guest distribution and write them
    /// to the `acpi_tables_bin` path in the metadata. Run this before `measure`.
    GenAcpi {
        /// Path to metadata json file.
        metadata: PathBuf,
        /// Guest distribution to build the QEMU ACPI dumper for.
        /// Supported: ubuntu:24.04, ubuntu:25.04, ubuntu:26.04.
        #[arg(long, value_name = "DISTRIBUTION", value_parser = ["ubuntu:24.04", "ubuntu:25.04", "ubuntu:26.04"])]
        distribution: String,
        /// Override the pinned QEMU source-package version. Defaults to the
        /// distribution's pinned version. Pass "" to use the current main-archive pick.
        #[arg(long, value_name = "QEMU_VERSION")]
        qemu_version: Option<String>,
    },

    /// Compute TDX measurements from a metadata.json.
    Measure(MeasureArgs),
}

fn run_measure(args: &MeasureArgs) -> Result<()> {
    let metadata = args
        .metadata
        .as_ref()
        .ok_or_else(|| anyhow!("metadata path is required"))?;
    // Load and deserialize metadata.json into Machine (paths resolved automatically)
    let machine = Machine::from_metadata_file(metadata)?;

    // Validate the configuration
    machine.validate()?;

    let measurements = machine
        .measure()
        .context("Failed to measure machine configuration")?;

    // Generate transcript (if requested).
    if let Some(ref transcript_file) = args.transcript {
        generate_transcript(transcript_file, &machine, false, false)?;
    }

    // Output results
    output_measurements(args, &measurements)?;

    Ok(())
}

fn run_gen_acpi(metadata: &Path, distribution: &str, qemu_version: &Option<String>) -> Result<()> {
    let machine = Machine::from_metadata_file(metadata)?;
    machine.validate()?;
    let qemu_options = machine
        .qemu_options
        .as_ref()
        .ok_or_else(|| anyhow!("qemu_options is required to generate ACPI tables"))?;
    let acpi_tables_bin = machine
        .measure_config
        .as_ref()
        .and_then(|mc| mc.acpi_tables_bin.as_deref())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("measure_config.acpi_tables_bin is required to generate ACPI tables"))?;
    let acpi_rsdp_bin = machine
        .measure_config
        .as_ref()
        .and_then(|mc| mc.rsdp.as_deref())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("measure_config.rsdp is required to generate ACPI tables"))?;
    let acpi_tables_loader = machine
        .measure_config
        .as_ref()
        .and_then(|mc| mc.table_loader.as_deref())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("measure_config.table_loader is required to generate ACPI tables"))?;
    acpi_dump::generate_acpi_tables(
        qemu_options,
        acpi_tables_bin,
        acpi_rsdp_bin,
        acpi_tables_loader,
        distribution,
        qemu_version.as_deref(),
    )
    .context("Failed to generate ACPI tables")?;
    Ok(())
}

fn output_measurements(args: &MeasureArgs, measurements: &tdx_measure::TdxMeasurements) -> Result<()> {
    let json_output = serde_json::to_string_pretty(measurements).unwrap();

    if args.json {
        println!("{}", json_output);
    } else {
        println!("Machine measurements:");
        println!("MRTD: {}", hex::encode(&measurements.mrtd));
        println!("RTMR0: {}", hex::encode(&measurements.rtmr0));
        println!("RTMR1: {}", hex::encode(&measurements.rtmr1));
        println!("RTMR2: {}", hex::encode(&measurements.rtmr2));
    }

    if let Some(ref json_file) = args.json_file {
        fs::write(json_file, json_output)
            .context("Failed to write measurements to file")?;
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::GenMetadata { qemu_command, boot_mode, tdvf_after_202411, output }) => {
            gen_metadata::run(qemu_command, boot_mode, !*tdvf_after_202411, output)?;
        }
        Some(Commands::GenAcpi { metadata, distribution, qemu_version }) => {
            run_gen_acpi(metadata, distribution, qemu_version)?;
        }
        Some(Commands::Measure(args)) => run_measure(args)?,
        None => run_measure(&cli.measure)?,
    }

    Ok(())
}
