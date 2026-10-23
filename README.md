# tdx-measure

## Scope
Command-line tool and Rust library to calculate expected measurement of an Intel TDX guest VM for confidential computing.

The `tdx-measure` tool takes a set of image binaries and platform config files as an input and outputs the corresponding TDX measurements. This makes it possible to exhaustively publish all images and config files that uniquely identify a TDX workload on a machine, making TD environments transparent and auditable.

Currently, the tool is able to pre-calculate measurements for the boot chains from the Canonical's Intel TDX [repo](https://github.com/canonical/tdx).
In particular, the measurement calculation was validated for TDs using Ubuntu 25.04 as guest OS running on Ubuntu 25.04 as host OS.
The building and execution of `tdx-measure` was validated on Ubuntu 25.04.

### Acknowledgment
This project is a fork of dstack-mr from the [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) repository.

## Usage

```tdx-measure [OPTIONS] <METADATA>```

Running `tdx-measure <METADATA>` (or the explicit `tdx-measure measure <METADATA>`
subcommand) computes the measurements. The tool also provides `gen-metadata`
(build a metadata skeleton from a QEMU command line) and `gen-acpi` (generate the
ACPI tables blob) subcommands.

### Arguments:
`<METADATA>` Path to metadata json file (see format lower down)

### Options
```
      --json                       Output JSON
      --json-file <JSON_FILE>      Output JSON to file
      --transcript <TRANSCRIPT>    Generate a human-readable transcript of all metadata files and write to the specified file
      --compare-eventlog[=<CCEL>]  Compare the computed events with a TDX CCEL event log and explain mismatches. Without a value, reads the running TD's log (/sys/firmware/acpi/tables/data/CCEL)
  -h, --help                       Print help
  -V, --version                    Print version
```

`--compare-eventlog` replays the event log and aligns it event-by-event with the
events computed by `tdx-measure`, marking each as matching (`=`), only in the log
(`-`) or only computed (`+`). For a mismatching GPT event it dumps the GPT from the
log next to the GPT read from the disk; for a mismatching initrd it reports whether
the initrd file was modified after boot and which `initrd*` file (if any) matches.
Inside a TD (`/dev/tdx_guest` present) it also reads the TDREPORT and compares the
computed MRTD and RTMR0–2 with the running TD's registers; for the TD's own event log
it also flags RTMRs whose log replay differs from the register.
Every mismatching event is listed under `=== Mismatch details ===` with its full
digest and a hex dump of the raw event-log entry. The output ends with a
`=== RESULT ===` verdict (`SUCCESS` or `FAILURE` with the list of mismatches), and
the command exits with status 1 on failure.
A log file path must be given with `=` (e.g. `--compare-eventlog=CCEL.bin`).
Running with `RUST_LOG=debug` additionally dumps the raw GPT event data computed
from the disk.

The boot mode (`direct` vs `indirect`) is determined by the `bootmode` field inside `measure_config` in the metadata file.

`measure` computes all four registers (MRTD, RTMR0–2) and therefore requires the
runtime inputs (kernel/initrd or qcow2). It reads the ACPI tables from the
`acpi_tables_bin` path in the metadata; generate that file first with `gen-acpi`
(or supply an externally-extracted one).

### Generating metadata from a QEMU command line

The `gen-metadata` subcommand parses a raw QEMU command line (via the bundled `qcparser` library) and emits a `metadata.json` skeleton:

```
tdx-measure gen-metadata --qemu-command <FILE> --boot-mode <direct|indirect> [--tdvf-after-202411] [-o metadata.json]
```

`--qemu-command` points to a file containing the QEMU invocation: a shell command line, or a running QEMU's `/proc/PID/cmdline` copied as-is (`cp /proc/PID/cmdline FILE`) or one argument per line (`tr '\0' '\n'`). Don't copy `cat /proc/PID/cmdline` from a terminal: that drops the argument separators, and `gen-metadata` rejects such a file. `--boot-mode` selects the boot chain and seeds the matching `measure_config` placeholder paths. `--tdvf-after-202411` marks the firmware as the 202411 build or newer (otherwise older firmware is assumed). The parsed VM shape is written to `qemu_options`; fill in the placeholder measurement-input paths afterwards.

Inside a running TD, `--in-guest` (indirect boot only) fills in `measure_config` instead of emitting placeholders: it points at the files written by [`extract_config_files.py`](extract_config_files.py) into `--dir` (default `.`), sets `cmdline` from `/proc/cmdline`, and sets `disk` to the disk backing `/boot/efi` (override with `--disk`; `--rootfs` defaults to `/`). `qemu_options` still comes from `--qemu-command`, so pass the QEMU command line the TD was launched with, then copy the host's OVMF image into the TD and point `qemu_options.bios` at it:

```
cd workdir && sudo python3 ../extract_config_files.py
sudo tdx-measure gen-metadata --qemu-command command --boot-mode indirect --in-guest
sudo tdx-measure metadata.json --compare-eventlog
```

### Direct Boot

#### Metadata

Create `metadata.json` file with the below metadata:

```
{
  "qemu_options": {
    "smp": "16",
    "memory": "2G",
    "bios": "[path to OVMF.fd]"
  },
  "measure_config": {
    "bootmode": "direct",
    "acpi_tables_bin": "[path to acpi_tables.bin]",
    "rsdp": "[path to rsdp.bin]",
    "table_loader": "[path to table_loader.bin]",
    "kernel": "[path to vmlinuz]",
    "initrd": "[path to initrd]",
    "cmdline": "root=/dev/sda1 console=ttyS0"
  }
}
```

#### Metadata Field Descriptions

- `qemu_options`: VM shape used to compute MRTD and RTMR[0] and (when generating ACPI tables) to launch QEMU.
  - `smp` *(optional)*: value passed verbatim to `-smp`, either a bare CPU count (`"16"`) or a full topology (`"48,sockets=1,dies=1,cores=24,threads=2"`). The topology affects the guest ACPI (MADT/SRAT), so preserve it verbatim. Defaults to a single CPU when absent.
  - `memory`: The amount of memory allocated to the TD (e.g., "2G" for 2 gigabytes). As with QEMU `-m`, a value without a suffix is in MiB ("16384" = 16 GiB).
  - `bios`: Path to file (e.g., `OVMF.fd`) containing a virtual BIOS, which is used to boot the TD image.
    The file can be obtained by setting up the host OS following [these instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#4-setup-host-os) and retrieving it from `/usr/share/ovmf/OVMF.fd`.
- `measure_config`: Measurement inputs. `bootmode` is `direct`.
  - `tdvf_before_202411` *(optional, default `true`)*: set to `false` when the TDVF firmware is the 202411 build or newer. When true, the separator event from RTMR1 is moved to the end of the RTMR0 measurement log.
  - `secure_boot` *(optional)*: override for the `SecureBoot` UEFI variable value (`false`/`true`). Normally omit it: the Secure Boot variables measured into RTMR[0] (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`, `dbt`) are derived from the OVMF image. `SecureBoot` only exists when OVMF is built with Secure Boot support (detected via `SecureBootConfigDxe`), and the keys come from the variable store in its CFV.
  - `acpi_tables_bin`: Path to a file containing ACPI tables, which describe the hardware configuration and device tree that the TD uses to discover and configure hardware.
    By using the `gen-acpi` subcommand of the `tdx-measure` tool, the ACPI tables are generated automatically and stored to a file at the path provided by `acpi_tables_bin`.
    Alternatively, a file containing the ACPI tables can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `rsdp`: Path to a file containing a Root System Description Pointer (RSDP), which is an ACPI data structure that provides the address of the RSDT/XSDT table.
    When omitted, the RSDP is derived automatically from the ACPI tables blob.
    Alternatively, a file containing the RSDP can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `table_loader`: Path to a file containing a ACPI table loader, which contains QEMU-specific commands for loading and patching ACPI tables.
    When omitted, the ACPI table loader is derived automatically from the ACPI tables blob.
    Alternatively, a file containing the table loader can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.

- `qemu_options` *(extended fields, optional)*: Generic QEMU shape descriptor consumed by `gen-acpi`. Each field is a thin pass-through to QEMU. When `machine` is present, the QEMU command is built from this block plus a minimal set of measurement-related core flags (`-smp ... -m ... -bios ... -nodefaults -vga none -nographic -no-reboot`). When absent, the tool falls back to the Canonical direct-boot args. Fields:
  - `machine`: value passed verbatim to `-machine`, e.g. `"q35,kernel_irqchip=split,memory-backend=mem0,smm=off,pic=off"`.
  - `cpu` *(optional, default `"host"`)*: value passed verbatim to `-cpu`. Use a named model with an explicit `phys-bits=N` (e.g. `"Skylake-Server,phys-bits=46"`) to make the run independent of the host CPU.
  - `accel` *(optional, default `"kvm"`)*: value passed verbatim to `-accel`. Use `"tcg"` to skip KVM (CI runners without `/dev/kvm`, ARM hosts via x86 emulation, …).
  - `globals`, `objects`, `numas`, `acpi_tables`, `netdevs`, `chardevs`, `blockdevs`, `drives`, `fw_cfg`: lists of strings, each emitted as the corresponding `-global` / `-object` / `-numa` / `-acpitable` / `-netdev` / `-chardev` / `-blockdev` / `-drive` / `-fw_cfg` argument.
  - `devices`: list of strings, each emitted as `-device <value>`. **Order is part of the API contract**: QEMU's PCI auto-slot assignment iterates `-device` arguments in command-line order and picks the lowest free slot, so `devices` must be authored in the same order as the reference launch you are mirroring. A `slot=N` argument on a `pcie-root-port` is only a hint and shifts if the slot is already taken by an earlier auto-assigned device. Order within `globals` / `objects` / `netdevs` / `fw_cfg` does not influence the ACPI tables.

- `measure_config` *(direct fields)*: Direct boot specific configuration used to compute RTMR[1] and RTMR[2]
  - `kernel`: Path to file (e.g., `vmlinuz`) of kernel image, which will be directly loaded and executed by OVMF.
    The file can be obtain by following [these instructions](https://github.com/canonical/tdx/tree/main/guest-tools/direct-boot#prerequisites).
  - `initrd`: Path to file (e.g., `initrd.img`) of initial RAM disk, which is a temporary root filesystem loaded into memory during boot, containing drivers and tools needed to mount the actual root filesystem.
    The file can be obtain by following the [these instructions](https://github.com/canonical/tdx/tree/main/guest-tools/direct-boot#prerequisites).
  - `cmdline`: Kernel command line parameters.
    These parameters specify the kernel command line arguments that are passed to QEMU using the `-append` option.

Note: For direct boot, `boot_order` and `path_boot_xxxx` do not need to be specified in the metadata file, as there is only one standardized BootOrder variable and a corresponding Boot#### UEFI variable.
These are calculated by the tool automatically.

#### Generating ACPI tables

The `gen-acpi` subcommand builds a small Docker image that
patches QEMU to dump `etc/acpi/tables` and exits before TD entry. This requires
a working `docker` (with buildx) and, when `accel: "kvm"` is in effect, KVM on
the host. Each supported distribution pins a known-good QEMU source version
(`1:9.2.1+ds-1ubuntu4+tdx2.0~ppa2` for `ubuntu:25.04`, `1:10.2.1+ds-1ubuntu4`
for `ubuntu:26.04`) so the same metadata produces the same ACPI bytes
regardless of when the regen runs. Pass `--qemu-version` to override the pin
(e.g. to validate an SRU), or `--qemu-version ""` to opt into whatever
`pull-lp-source` currently picks from the main archive. The tables are written
to the `acpi_tables_bin` path in the metadata:

```
tdx-measure gen-acpi <METADATA> --distribution ubuntu:26.04                                    # default pin
tdx-measure gen-acpi <METADATA> --distribution ubuntu:26.04 --qemu-version 1:10.2.1+ds-1ubuntu5 # explicit version
tdx-measure gen-acpi <METADATA> --distribution ubuntu:26.04 --qemu-version ""                   # current main-archive tip
```

The dumper itself lives in the standalone `acpi-dump` library crate; the core
`tdx-measure` measurement library carries no Docker/process dependencies.

### Indirect Boot

#### Metadata

Create `metadata.json` file with the below metadata:

```
{
  "qemu_options": {
    "smp": "32",
    "memory": "10G",
    "bios": "[path to OVMF.fd]"
  },
  "measure_config": {
    "bootmode": "indirect",
    "acpi_tables_bin": "[path to acpi_tables.bin]",
    "rsdp": "[path to rsdp.bin]",
    "table_loader": "[path to table_loader.bin]",
    "boot_order": "[path to BootOrder.bin]",
    "boot_current": "[path to BootCurrent.bin]",
    "path_boot_xxxx": "[path to directory containing Bootxxxx.bin files]",
    "qcow2": "[path to tdx-guest-ubuntu-25.04-generic.qcow2]",
    "cmdline": "console=ttyS0 root=/dev/vda1",
    "mok_list": "[path to MokList.bin]",
    "mok_list_trusted": "[path to MokListTrusted.bin]",
    "mok_list_x": "[path to MokListX.bin]",
    "sbat_level": "[path to SbatLevel.bin]"
  }
}
```

#### Metadata Field Descriptions

- `qemu_options`: VM shape used to compute MRTD and RTMR[0]
  - `cpus`: Number of virtual CPUs allocated to the TD.
  - `memory`: The amount of memory allocated to the TD (e.g., "2G" for 2 gigabytes). As with QEMU `-m`, a value without a suffix is in MiB ("16384" = 16 GiB).
  - `bios`: Path to file (e.g., `OVMF.fd`) containing a virtual BIOS, which is used to boot the TD image.
    The file can be obtained by setting up the host OS following [these instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#4-setup-host-os) and retrieving it from `/usr/share/ovmf/OVMF.fd`.
- `measure_config`: Measurement inputs. `bootmode` is `indirect`.
  - `tdvf_before_202411` *(optional, default `true`)*: set to `false` when the TDVF firmware is the 202411 build or newer. When true, the separator event from RTMR1 is moved to the end of the RTMR0 measurement log.
  - `secure_boot` *(optional)*: override for the `SecureBoot` UEFI variable value (`false`/`true`). Normally omit it: the Secure Boot variables measured into RTMR[0] (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`, `dbt`) are derived from the OVMF image. `SecureBoot` only exists when OVMF is built with Secure Boot support (detected via `SecureBootConfigDxe`), and the keys come from the variable store in its CFV.
  - `acpi_tables_bin`: Path to file containing ACPI tables, which describe the hardware configuration and device tree that the TD uses to discover and configure hardware.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `rsdp`: Path to file containing a Root System Description Pointer (RSDP), which is an ACPI data structure that provides the address of the RSDT/XSDT table.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `table_loader`: Path to file containing a ACPI table loader, which contains QEMU-specific commands for loading and patching ACPI tables.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `boot_order`: Path to file containing a UEFI BootOrder variable, which specifies the order in which the firmware attempts to boot from different boot options.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `path_boot_xxxx`: Path to directory containing files (e.g., `Boot0000.bin`, `Boot0001.bin`, `Boot0002.bin`) for each Boot#### UEFI variables.
    Each variable defines a specific boot option with its device path and description.
    These files can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `boot_current` *(optional)*: Path to file containing the UEFI BootCurrent variable, captured by [`extract_config_files.py`](extract_config_files.py) in the TD whose boot is being measured. Used to detect a shim fallback boot (see `shim_fallback`). `gen-metadata` emits it for indirect boot; remove it to predict the boot from the `qcow2` image instead.
  - `shim_fallback` *(optional)*: override for whether firmware boots via shim's fallback path, `\EFI\BOOT\BOOTX64.EFI` → `fbx64.efi` → `\EFI\ubuntu\shimx64.efi`. OVMF does this when no OS boot entry exists, i.e. when the ESP has no `/NvVars` (e.g. the first boot of a fresh image). Such a boot additionally measures BOOTX64.EFI and fbx64.efi into RTMR[1], measures the MOK variables twice in RTMR[2] and SbatLevel twice in RTMR[0], and the boot entries created by fbx64.efi are not part of the measured BootOrder. Normally omit it: in-guest it is detected from `boot_current` (the booted entry has no file path), and with `qcow2` it is predicted from whether `/boot/efi/NvVars` exists in the image.

- `measure_config` *(indirect fields)*: used to compute RTMR[1] and RTMR[2]
  - `qcow2`: Path to guest OS disk image in QCOW2 format.
    The image contains the guest filesystem with the bootloader chain (e.g., SHIM and Grub) and a kernel.
    The image can be created by following [these instructions](https://github.com/canonical/tdx/tree/main?tab=readme-ov-file#5-create-td-image).
  - `disk` *(alternative to `qcow2`)*: Raw boot disk of the running guest (e.g. `/dev/vda`), used when running `tdx-measure` **inside the TD**.
    The GPT is read from this device, and shim/grub/initrd are read from the local filesystem under `rootfs`. Requires read access to the device (typically root). `qcow2` and `disk` are mutually exclusive.
  - `rootfs` *(optional, used with `disk`, default `/`)*: Guest filesystem root from which `/boot/efi/EFI/ubuntu/{shimx64,grubx64}.efi` and `/boot/initrd.img-<version>` are read.
  - `cmdline`: Kernel command line parameters.
    These parameters can be obtained by executing `cat /proc/cmdline` inside a TD, which is configured identically to the target configuration.
  - `mok_list`: Path to file containing a Machine Owner Key (MOK) list for Secure Boot.
    Contains user-enrolled keys that supplement the vendor-provided Secure Boot keys.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `mok_list_trusted`: Path to file containing a MOK trusted list.
    Contains additional trusted keys for Secure Boot verification.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `mok_list_x`: Path to file containing a MOK blacklist (forbidden keys).
    Contains keys that have been explicitly revoked and should not be trusted.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.
  - `sbat_level`: Path to file containing a SBAT (Secure Boot Advanced Targeting) revocation list.
    Used to revoke specific bootloader versions without revoking their signing keys.
    The file can be extracted by running the [`extract_config_files.py`](extract_config_files.py) script inside a TD, which is configured identically to the target configuration.

### Transcript

The transcript flag makes it possible to generate a human-readable transcript from the different binary configuration files. The command line tool `iasl` needs to be installed in order to disassembled the ACPI tables and include its representation in the transcript.

## Prerequisite

### Install Rust

[If not already done] Install Rust dependency, install Rust, activate it in the current shell, and test the installation:
```
sudo apt update
sudo apt install build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cargo --version
```
See [Rust's installation documentation](https://www.rust-lang.org/tools/install) for more detailed information.

### Install jq

> [!NOTE]
> This prerequisite is only required when generating ACPI tables in Direct Mode with `--create-acpi-tables`.

[If not already done] Install jq with the following command:
```
sudo apt-get install jq
```

### Install Docker

> [!NOTE]
> This prerequisite is only required when generating ACPI tables in Direct Mode with `--create-acpi-tables`.

> [!NOTE]
> See [Docker's installation documentation](https://docs.docker.com/engine/install/ubuntu/) and [Docker's post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/) for more detailed information.

[If not already done] Install Docker with the following steps:

1. Add Docker's official GPG key:
    ```
    sudo apt update
    sudo apt install ca-certificates curl
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc
    ```

2. Add Docker's package repository:
    ```
    sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
    Types: deb
    URIs: https://download.docker.com/linux/ubuntu
    Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
    Components: stable
    Signed-By: /etc/apt/keyrings/docker.asc
    EOF
    ```

3. Install the Docker packages:
    ```
    sudo apt update
    sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ```

4. Manage Docker as a non-root user:
    ```
    sudo groupadd docker
    sudo usermod -aG docker $USER
    ```

    - Log out and log back in so that your group membership is re-evaluated.
    - Alternatively, execute the following command to activate the changes to groups:
        ```
        newgrp docker
        ```

## Build the project

```
cargo build --release
```

## Install the CLI tool

```
cargo install --path cli
```



## Info

### Boot Methods
Canonical repo offer two boot options:

1) Direct Boot:
With this method, `OVMF` (the TDVF or virtual firmware) directly boots the kernel image. In this mode, the `kernel`, `initrd` and the kernel `cmdline` are directly supplied to `qemu`.

2) Indirect Boot:
With this method, `tdvirsh` is used to run TDs, the boot chain is more complex and involves `OVMF`, a `SHIM`, `Grub`, and finally the `kernel`+`initrd` image.

### What goes in the measurements

TDX attestation reports expose 4 measurement registers (MR).

The first one, `MRTD`, represent the measurements for the TD virtual firmware binary (TDVF, specifically OVMF.fd in our case).

Three other runtime measurement registers (`RTMR`) correspond to different boot stages and vary depending on the boot chain.

`RTMR[0]` contains firmware configuration and platform specific measurements. This includes hashes of:
- The TD HOB which mostly contains a description of the memory accessible to the TD.
- TDX configuration values.
- Various Secure Boot variables.
- ACPI tables that describe the device tree.
- Boot variables (BootOrder and others).
- [for indirect boot only] [SbatLevel](https://github.com/rhboot/shim/blob/main/SbatLevel_Variable.txt) variable.

`RTMR[1]` contains measurements of the `kernel` for direct boot. For indirect boot, it contains measurement for the bootchain a.k.a. `gpt` (GUID Partition Table), `shim`, and `grub`.

`RTMR[2]` contains measurements of the kernel `cmdline` and `initrd` for direct boot. For indirect boot, it also contains the measurements of machine owner key [(MOK) variables](https://github.com/rhboot/shim/blob/main/MokVars.txt).
