/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! A GRUB 2.06 script interpreter that replays the boot flow far enough to
//! reproduce what GRUB's TPM/CC verifier measures into RTMR2: every executed
//! command line (`grub_cmd: ...`), the kernel command line
//! (`kernel_cmdline: ...`) and every file it opens from disk.

use super::efi::{module_deps, module_name, GrubImage};
use super::script::{self, Arg, Cmd, Seg};
use crate::util::measure_sha384;
use anyhow::{bail, Context as _, Result};
use log::{debug, warn};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

const ERR_TEST_FAILURE: i32 = 1;
const ERR_BAD_MODULE: i32 = 2;
const ERR_BAD_FILE_TYPE: i32 = 4;
const ERR_FILE_NOT_FOUND: i32 = 5;
const ERR_BAD_ARGUMENT: i32 = 18;
const ERR_NO_KERNEL: i32 = 22;
const ERR_BAD_FONT: i32 = 23;
const ERR_MENU: i32 = 27;

const MAX_DEPTH: usize = 64;
const MAX_STEPS: usize = 100_000;
const GRUBENV_HEADER: &str = "# GRUB Environment Block\n";

/// Kind of a filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

/// The boot disk as GRUB sees it (`hd0`), addressed by GPT partition number
/// (`hd0,gptN`, 1-based entry index). Paths are absolute within the
/// partition's filesystem.
pub trait GrubDisk {
    /// Non-empty partitions in partition-table order.
    fn partitions(&mut self) -> Result<Vec<u32>>;
    /// The GRUB module that reads the partition's filesystem (e.g. `ext2`,
    /// `fat`), `None` if GRUB recognizes none.
    fn fs_module(&mut self, part: u32) -> Result<Option<String>>;
    fn stat(&mut self, part: u32, path: &str) -> Result<Option<Kind>>;
    /// Contents of a regular file, `None` if it does not exist.
    fn read(&mut self, part: u32, path: &str) -> Result<Option<Vec<u8>>>;
    fn fs_uuid(&mut self, part: u32) -> Result<Option<String>>;
    fn fs_label(&mut self, part: u32) -> Result<Option<String>>;
}

/// One measurement made by GRUB's verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrubEvent {
    Command(String),
    KernelCmdline(String),
    File { name: String, digest: Vec<u8> },
}

impl GrubEvent {
    pub fn digest(&self) -> Vec<u8> {
        match self {
            GrubEvent::Command(s) | GrubEvent::KernelCmdline(s) => measure_sha384(s.as_bytes()),
            GrubEvent::File { digest, .. } => digest.clone(),
        }
    }

    /// The event description GRUB logs.
    pub fn description(&self) -> String {
        match self {
            GrubEvent::Command(s) => format!("grub_cmd: {s}"),
            GrubEvent::KernelCmdline(s) => format!("kernel_cmdline: {s}"),
            GrubEvent::File { name, .. } => name.clone(),
        }
    }
}

/// Result of replaying a GRUB boot.
#[derive(Debug, Clone)]
pub struct GrubBoot {
    pub events: Vec<GrubEvent>,
    /// Kernel path as passed to `linux`.
    pub kernel: String,
    /// The loader command line GRUB built (kernel path plus arguments).
    pub loader_cmdline: String,
    pub initrds: Vec<String>,
}

impl GrubBoot {
    /// The command line the kernel sees (`/proc/cmdline`).
    pub fn kernel_cmdline(&self) -> String {
        format!("BOOT_IMAGE={}", self.loader_cmdline)
    }
}

/// Replay GRUB booting from the ESP partition `esp` with `fw_path` (e.g.
/// `/EFI/debian`) as the directory GRUB was loaded from.
pub fn simulate(
    image: &GrubImage,
    disk: &mut dyn GrubDisk,
    esp: u32,
    fw_path: &str,
) -> Result<GrubBoot> {
    let mut grub = Grub::new(image, disk);
    grub.boot(esp, fw_path)?;
    let Some((kernel, loader_cmdline)) = grub.kernel.take() else {
        bail!("GRUB replay finished without booting a kernel");
    };
    Ok(GrubBoot {
        events: grub.events,
        kernel,
        loader_cmdline,
        initrds: grub.initrds,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Dev {
    Mem,
    Disk,
    Part(u32),
}

fn parse_dev(s: &str) -> Option<Dev> {
    match s {
        "memdisk" => Some(Dev::Mem),
        "hd0" => Some(Dev::Disk),
        _ => {
            let p = s.strip_prefix("hd0,")?;
            let p = p.strip_prefix("gpt").unwrap_or(p);
            p.parse().ok().filter(|&n| n > 0).map(Dev::Part)
        }
    }
}

fn normalize(path: &str) -> String {
    let mut out = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        out.push('/');
        out.push_str(part);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

fn split_ws(s: &str) -> Vec<String> {
    s.split(is_space)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `grub_strtoul(s, &end, 0)`: the leading number, `None` if there is none.
fn strtoul(s: &str) -> Option<u64> {
    let s = s.trim_start_matches(is_space);
    let (digits, radix) = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (h, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if end == 0 {
        return (radix == 8).then_some(0);
    }
    u64::from_str_radix(&digits[..end], radix).ok()
}

fn strtosl(s: &str) -> i64 {
    let t = s.trim_start_matches(is_space);
    match t.strip_prefix('-') {
        Some(r) => -(strtoul(r).unwrap_or(0) as i64),
        None => strtoul(t).unwrap_or(0) as i64,
    }
}

/// GRUB's `menuentry_eq`: does entry `id` match `spec` up to an unescaped `>`?
fn menuentry_eq(id: &str, spec: &str) -> bool {
    let (a, b) = (id.as_bytes(), spec.as_bytes());
    let (mut i, mut j) = (0, 0);
    loop {
        let c2 = b.get(j).copied().unwrap_or(0);
        let gt = c2 == b'>' && b.get(j + 1) != Some(&b'>');
        let c1 = a.get(i).copied().unwrap_or(0);
        if gt {
            return c1 == 0;
        }
        if c2 == b'>' {
            j += 1;
        }
        let c2 = b.get(j).copied().unwrap_or(0);
        if c1 != c2 {
            return false;
        }
        if c1 == 0 {
            return true;
        }
        i += 1;
        j += 1;
    }
}

/// `grub_create_loader_cmdline`.
fn loader_cmdline(args: &[String]) -> String {
    let mut out = Vec::new();
    for arg in args {
        let mut s = String::new();
        let space = arg.contains(' ');
        if space {
            s.push('"');
        }
        for c in arg.chars() {
            if matches!(c, '\\' | '\'' | '"') {
                s.push('\\');
            }
            s.push(c);
        }
        if space {
            s.push('"');
        }
        out.push(s);
    }
    out.join(" ")
}

struct Var {
    value: String,
    exported: bool,
}

#[derive(Clone)]
struct MenuEntry {
    title: String,
    id: String,
    args: Vec<String>,
    source: String,
    submenu: bool,
}

#[derive(Default)]
struct Context {
    vars: HashMap<String, Var>,
    menu: Option<Vec<MenuEntry>>,
}

enum Flow {
    Next,
    Break(usize),
    Continue(usize),
    Return,
    Halt,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SearchKind {
    File,
    FsUuid,
    Label,
}

#[derive(Clone, Copy, PartialEq)]
enum OptKind {
    Flag,
    Value,
    /// Value only in `--opt=value` form.
    OptValue,
}

struct Opt {
    long: &'static str,
    short: Option<char>,
    kind: OptKind,
}

const fn opt(long: &'static str, short: Option<char>, kind: OptKind) -> Opt {
    Opt { long, short, kind }
}

/// Parsed extcmd options: long name -> values (one per occurrence).
type Opts = HashMap<&'static str, Vec<Option<String>>>;

/// `grub_arg_parse`. Returns `None` on an unrecognized option.
fn parse_opts(args: &[String], specs: &[Opt], accept_dash: bool) -> Option<(Opts, Vec<String>)> {
    let mut opts: Opts = HashMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    let mut only_pos = false;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if only_pos || !a.starts_with('-') || a == "-" {
            pos.push(a.clone());
            continue;
        }
        if a == "--" {
            only_pos = true;
            continue;
        }
        let (spec, inline) = if let Some(long) = a.strip_prefix("--") {
            let (name, val) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            (specs.iter().find(|s| s.long == name), val)
        } else {
            let mut chars = a[1..].chars();
            let c = chars.next();
            let rest: String = chars.collect();
            let spec = specs.iter().find(|s| s.short.is_some() && s.short == c);
            (spec, (!rest.is_empty()).then_some(rest))
        };
        let Some(spec) = spec else {
            if accept_dash {
                pos.push(a.clone());
                continue;
            }
            return None;
        };
        let value = match spec.kind {
            OptKind::Flag => None,
            OptKind::OptValue => inline,
            OptKind::Value => match inline {
                Some(v) => Some(v),
                None => {
                    let v = args.get(i)?.clone();
                    i += 1;
                    Some(v)
                }
            },
        };
        opts.entry(spec.long).or_default().push(value);
    }
    Some((opts, pos))
}

fn opt_value(opts: &Opts, name: &str) -> Option<String> {
    opts.get(name).and_then(|v| v.last().cloned().flatten())
}

fn opt_values(opts: &Opts, name: &str) -> Vec<String> {
    opts.get(name)
        .map(|v| v.iter().flatten().cloned().collect())
        .unwrap_or_default()
}

/// Commands this interpreter knows; anything else is treated as a command
/// without side effects that matter for measurement.
const NOOP_COMMANDS: &[&str] = &[
    "echo",
    "serial",
    "terminfo",
    "sleep",
    "fwsetup",
    "play",
    "clear",
    "cpuid",
    "videoinfo",
    "lsefi",
    "lsefisystab",
    "lsefimmap",
    "smbios",
    "gettext",
    "help",
    "list_env",
    "gfxmode",
    "lsmod",
    "date",
    "halt",
    "reboot",
    "exit",
    "normal_exit",
    "rmmod",
    "set_gfxpayload",
];

/// Commands that read files or change the boot flow in ways not modelled.
const UNSUPPORTED_COMMANDS: &[&str] = &[
    "chainloader",
    "loopback",
    "background_image",
    "cat",
    "hexdump",
    "cmp",
    "hashsum",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "crc",
    "multiboot",
    "multiboot2",
    "module",
    "module2",
    "acpi",
    "devicetree",
    "verify_detached",
    "trust",
    "distrust",
    "cryptomount",
    "linux16",
    "initrd16",
    "xnu_kernel",
    "xnu_kernel64",
    "legacy_configfile",
    "extract_entries_configfile",
    "extract_entries_source",
    "probe",
    "regexp",
    "ls",
    "fakebios",
    "badram",
    "cutmem",
];

struct Grub<'a> {
    image: &'a GrubImage,
    disk: &'a mut dyn GrubDisk,
    ctxs: Vec<Context>,
    scopes: Vec<Vec<String>>,
    functions: HashMap<String, Rc<Vec<Cmd>>>,
    loaded: HashSet<String>,
    dyncmds: HashMap<String, String>,
    terminal_mods: Vec<(String, String)>,
    /// Remaining `fs.lst` modules; `None` until the autoload hook is set.
    fs_autoload: Option<Vec<String>>,
    autoload_enabled: bool,
    in_autoload: bool,
    lists_hook: bool,
    loops: usize,
    search_cache: Vec<(SearchKind, String, String)>,
    overlay: HashMap<(u32, String), Vec<u8>>,
    kernel: Option<(String, String)>,
    initrds: Vec<String>,
    events: Vec<GrubEvent>,
    last_ret: i32,
    depth: usize,
    steps: usize,
    gfxterm: bool,
    halted: bool,
}

impl<'a> Grub<'a> {
    fn new(image: &'a GrubImage, disk: &'a mut dyn GrubDisk) -> Self {
        Grub {
            image,
            disk,
            ctxs: vec![Context::default()],
            scopes: Vec::new(),
            functions: HashMap::new(),
            loaded: image.modules.iter().cloned().collect(),
            dyncmds: HashMap::new(),
            terminal_mods: Vec::new(),
            fs_autoload: None,
            autoload_enabled: true,
            in_autoload: false,
            lists_hook: false,
            loops: 0,
            search_cache: Vec::new(),
            overlay: HashMap::new(),
            kernel: None,
            initrds: Vec::new(),
            events: Vec::new(),
            last_ret: 0,
            depth: 0,
            steps: 0,
            gfxterm: false,
            halted: false,
        }
    }

    // ---- environment ----------------------------------------------------

    fn ctx(&mut self) -> &mut Context {
        self.ctxs.last_mut().unwrap()
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.ctxs
            .last()
            .unwrap()
            .vars
            .get(name)
            .map(|v| v.value.as_str())
    }

    fn get_owned(&self, name: &str) -> Option<String> {
        self.get(name).map(str::to_owned)
    }

    fn set_raw(&mut self, name: &str, value: &str) {
        let vars = &mut self.ctx().vars;
        match vars.get_mut(name) {
            Some(v) => v.value = value.to_string(),
            None => {
                vars.insert(
                    name.to_string(),
                    Var {
                        value: value.to_string(),
                        exported: false,
                    },
                );
            }
        }
    }

    /// `grub_env_set`, including the write hooks GRUB registers.
    fn set(&mut self, name: &str, value: &str) -> Result<()> {
        match name {
            "prefix" if self.lists_hook => self.read_lists(Some(value))?,
            "lang" => {
                let (dir, prefix) = (self.get_owned("locale_dir"), self.get_owned("prefix"));
                self.gettext(Some(value), dir.as_deref(), prefix.as_deref())?;
            }
            "locale_dir" => {
                let (lang, prefix) = (self.get_owned("lang"), self.get_owned("prefix"));
                self.gettext(lang.as_deref(), Some(value), prefix.as_deref())?;
            }
            _ => {}
        }
        self.set_raw(name, value);
        Ok(())
    }

    fn has_hook(&self, name: &str) -> bool {
        matches!(name, "lang" | "locale_dir" | "secondary_locale_dir")
            || (name == "prefix" && self.lists_hook)
    }

    fn unset(&mut self, name: &str) -> Result<()> {
        if self.has_hook(name) {
            return self.set(name, "");
        }
        self.ctx().vars.remove(name);
        Ok(())
    }

    fn export(&mut self, name: &str) -> Result<()> {
        if self.get(name).is_none() {
            self.set(name, "")?;
        }
        self.ctx().vars.get_mut(name).unwrap().exported = true;
        Ok(())
    }

    fn set_exported(&mut self, name: &str, value: &str) -> Result<()> {
        self.set(name, value)?;
        self.export(name)
    }

    fn context_open(&mut self) {
        let vars = self
            .ctxs
            .last()
            .unwrap()
            .vars
            .iter()
            .filter(|(_, v)| v.exported)
            .map(|(k, v)| {
                (
                    k.clone(),
                    Var {
                        value: v.value.clone(),
                        exported: true,
                    },
                )
            })
            .collect();
        self.ctxs.push(Context { vars, menu: None });
    }

    fn context_close(&mut self) {
        if self.ctxs.len() > 1 {
            self.ctxs.pop();
        }
    }

    fn set_status(&mut self, ret: i32) {
        self.last_ret = ret;
        self.set_raw("?", &ret.to_string());
    }

    fn prefix(&self) -> Option<String> {
        self.get_owned("prefix")
    }

    // ---- files ----------------------------------------------------------

    /// Split a GRUB file name into device and path; `None` for an unknown
    /// device.
    fn resolve(&self, name: &str) -> Option<(Dev, String)> {
        if let Some(rest) = name.strip_prefix('(') {
            let close = rest.find(')')?;
            Some((parse_dev(&rest[..close])?, rest[close + 1..].to_string()))
        } else {
            Some((parse_dev(self.get("root")?)?, name.to_string()))
        }
    }

    /// `grub_fs_probe`: the device is readable once the module of its
    /// filesystem is loaded. Failing that, GRUB's `fs.lst` autoload hook
    /// loads (and measures) the not yet loaded modules one at a time until
    /// one recognizes the device.
    fn probe(&mut self, dev: &Dev) -> Result<bool> {
        let module = match dev {
            Dev::Mem => return Ok(self.image.memdisk.is_some()),
            Dev::Disk => None,
            Dev::Part(n) => self.disk.fs_module(*n)?,
        };
        if module.as_ref().is_some_and(|m| self.loaded.contains(m)) {
            return Ok(true);
        }
        if !self.autoload_enabled || self.in_autoload {
            return Ok(false);
        }
        self.in_autoload = true;
        let r = self.autoload_fs(module.as_deref());
        self.in_autoload = false;
        r
    }

    fn autoload_fs(&mut self, module: Option<&str>) -> Result<bool> {
        while let Some(m) = self
            .fs_autoload
            .as_mut()
            .filter(|l| !l.is_empty())
            .map(|l| l.remove(0))
        {
            if self.loaded.contains(&m) {
                continue;
            }
            if self.load_module(&m)? == 0 && module == Some(m.as_str()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `grub_file_open`: returns the contents and measures them if `measure`
    /// and the file lives on the disk.
    fn open(&mut self, name: &str, measure: bool) -> Result<Option<Vec<u8>>> {
        let Some((dev, path)) = self.resolve(name) else {
            return Ok(None);
        };
        if !self.probe(&dev)? || !path.starts_with('/') {
            return Ok(None);
        }
        let data = match dev {
            Dev::Mem => self
                .image
                .memdisk
                .as_ref()
                .and_then(|m| m.file(&path))
                .map(<[u8]>::to_vec),
            Dev::Disk => None,
            Dev::Part(n) => {
                let path = normalize(&path);
                match self.overlay.get(&(n, path.clone())) {
                    Some(d) => Some(d.clone()),
                    None => self.disk.read(n, &path)?,
                }
            }
        };
        if let (Some(d), true, Dev::Part(_)) = (&data, measure, &dev) {
            self.events.push(GrubEvent::File {
                name: name.to_string(),
                digest: measure_sha384(d),
            });
        }
        Ok(data)
    }

    /// The `get_fileinfo` used by `test -e/-f/-d`.
    fn stat(&mut self, name: &str) -> Result<Option<Kind>> {
        let Some((dev, path)) = self.resolve(name) else {
            return Ok(None);
        };
        if !self.probe(&dev)? {
            return Ok(None);
        }
        let path = path.trim_end_matches('/');
        if path.is_empty() {
            return Ok(Some(Kind::Dir));
        }
        Ok(match dev {
            Dev::Mem => {
                let m = self.image.memdisk.as_ref().unwrap();
                if m.file(path).is_some() {
                    Some(Kind::File)
                } else if m.is_dir(path) {
                    Some(Kind::Dir)
                } else {
                    None
                }
            }
            Dev::Disk => None,
            Dev::Part(n) => {
                let path = normalize(path);
                if self.overlay.contains_key(&(n, path.clone())) {
                    Some(Kind::File)
                } else {
                    self.disk.stat(n, &path)?
                }
            }
        })
    }

    // ---- lists, modules and gettext -------------------------------------

    fn read_lists(&mut self, prefix: Option<&str>) -> Result<()> {
        if let Some(prefix) = prefix {
            if let Some(d) = self.open(&format!("{prefix}/x86_64-efi/command.lst"), true)? {
                self.dyncmds.clear();
                for line in String::from_utf8_lossy(&d).lines() {
                    if let Some((name, module)) = line.trim_start().split_once(':') {
                        let name = name.trim_start_matches('*').trim();
                        self.dyncmds
                            .insert(name.to_string(), module.trim().to_string());
                    }
                }
            }
            if let Some(d) = self.open(&format!("{prefix}/x86_64-efi/fs.lst"), true)? {
                let mut list: Vec<String> = String::from_utf8_lossy(&d)
                    .lines()
                    .map(str::trim)
                    .filter(|l| l.len() > 1)
                    .map(str::to_owned)
                    .collect();
                list.reverse();
                self.fs_autoload = Some(list);
            }
            self.open(&format!("{prefix}/x86_64-efi/crypto.lst"), true)?;
            if let Some(d) = self.open(&format!("{prefix}/x86_64-efi/terminal.lst"), true)? {
                self.terminal_mods = String::from_utf8_lossy(&d)
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .map(|(n, m)| (n.trim().to_string(), m.trim().to_string()))
                    .collect();
            }
        }
        if self.fs_autoload.is_none() {
            self.fs_autoload = Some(Vec::new());
        }
        let (lang, dir) = (self.get_owned("lang"), self.get_owned("locale_dir"));
        self.gettext(lang.as_deref(), dir.as_deref(), prefix)
    }

    /// `grub_gettext_init_ext`: open the first existing catalog.
    fn gettext(
        &mut self,
        lang: Option<&str>,
        dir: Option<&str>,
        prefix: Option<&str>,
    ) -> Result<()> {
        let Some(lang) = lang.filter(|l| !l.is_empty()) else {
            return Ok(());
        };
        let (p1, p2) = match dir.filter(|d| !d.is_empty()) {
            Some(d) => (d, ""),
            None => (prefix.unwrap_or(""), "/locale"),
        };
        if p1.is_empty() {
            return Ok(());
        }
        let mut langs = vec![lang.to_string()];
        if let Some((short, _)) = lang.split_once('_') {
            langs.push(short.to_string());
        }
        for l in langs {
            for ext in ["mo", "mo.gz", "gmo"] {
                if self.open(&format!("{p1}{p2}/{l}.{ext}"), true)?.is_some() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// `grub_dl_load`.
    fn load_module(&mut self, name: &str) -> Result<i32> {
        if self.loaded.contains(name) {
            return Ok(0);
        }
        let Some(prefix) = self.prefix() else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        self.load_module_file(&format!("{prefix}/x86_64-efi/{name}.mod"))
    }

    /// `grub_dl_load_file`.
    fn load_module_file(&mut self, path: &str) -> Result<i32> {
        let Some(data) = self.open(path, true)? else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Ok(Some(name)) = module_name(&data) else {
            return Ok(ERR_BAD_MODULE);
        };
        if self.loaded.contains(&name) {
            return Ok(ERR_BAD_MODULE);
        }
        for dep in module_deps(&data).unwrap_or_default() {
            let r = self.load_module(&dep)?;
            if r != 0 {
                return Ok(r);
            }
        }
        debug!("grub: loaded module {name} from {path}");
        self.loaded.insert(name);
        Ok(0)
    }

    // ---- boot flow --------------------------------------------------------

    fn boot(&mut self, esp: u32, fw_path: &str) -> Result<()> {
        let fwdev = format!("hd0,gpt{esp}");
        let (root, prefix) = match self.image.prefix.as_deref().filter(|p| !p.is_empty()) {
            Some(p) if p.starts_with('(') => {
                let close = p.find(')').context("bad GRUB prefix")?;
                (p[1..close].to_string(), p.to_string())
            }
            Some(p) => (fwdev.clone(), format!("({fwdev}){p}")),
            None => (fwdev.clone(), format!("({fwdev}){fw_path}")),
        };
        self.set_exported("cmdpath", &format!("({fwdev}){fw_path}"))?;
        self.set_exported("prefix", &prefix)?;
        self.set_exported("root", &root)?;
        for v in ["lang", "locale_dir", "secondary_locale_dir"] {
            self.export(v)?;
        }
        self.set_exported("color_normal", "light-gray/black")?;
        self.set_exported("color_highlight", "black/light-gray")?;
        for f in [
            "feature_chainloader_bpb",
            "feature_ntldr",
            "feature_platform_search_hint",
            "feature_default_font_path",
            "feature_all_video_module",
            "feature_menuentry_id",
            "feature_menuentry_options",
            "feature_200_final",
            "feature_nativedisk_cmd",
            "feature_timeout_style",
        ] {
            self.set_exported(f, "y")?;
        }
        self.set_exported("grub_cpu", "x86_64")?;
        self.set_exported("grub_platform", "efi")?;

        // The embedded config runs through the rescue parser, which does not
        // measure command lines.
        if let Some(config) = self.image.config.clone() {
            for line in config.lines() {
                let cmds =
                    script::parse(line).with_context(|| format!("embedded GRUB config: {line}"))?;
                for cmd in &cmds {
                    if let Cmd::Simple(args) = cmd {
                        if let Flow::Halt = self.exec_simple(args, false)? {
                            return Ok(());
                        }
                    }
                }
            }
        }
        if !self.halted {
            self.cmd_normal(&[])?;
        }
        Ok(())
    }

    fn cmd_normal(&mut self, args: &[String]) -> Result<Flow> {
        let config = match args.first() {
            Some(c) => Some(c.clone()),
            None => self.prefix().map(|p| format!("{p}/grub.cfg")),
        };
        self.normal_execute(config.as_deref(), false, false)?;
        if self.halted {
            return Ok(Flow::Halt);
        }
        bail!("GRUB fell through to its interactive command line without booting");
    }

    /// `grub_normal_execute`.
    fn normal_execute(&mut self, config: Option<&str>, nested: bool, batch: bool) -> Result<i32> {
        if !nested {
            let prefix = self.prefix();
            self.read_lists(prefix.as_deref())?;
            self.lists_hook = true;
        }
        let mut ret = 0;
        if let Some(config) = config {
            ret = self.read_config_file(config)?;
            if self.halted {
                return Ok(0);
            }
        }
        if !batch {
            let menu = self.ctx().menu.clone().unwrap_or_default();
            if !menu.is_empty() {
                self.show_menu(nested, false)?;
            }
        }
        Ok(ret)
    }

    fn read_config_file(&mut self, config: &str) -> Result<i32> {
        if self.ctx().menu.is_none() {
            self.ctx().menu = Some(Vec::new());
        }
        let Some(data) = self.open(config, true)? else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let (old_file, old_dir) = (
            self.get_owned("config_file"),
            self.get_owned("config_directory"),
        );
        let file = if config.starts_with('(') {
            config.to_string()
        } else {
            format!("({}){config}", self.get("root").unwrap_or(""))
        };
        let dir = file
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| file.clone());
        self.set_exported("config_file", &file)?;
        self.set_exported("config_directory", &dir)?;
        let src = script::config_source(&data);
        let cmds =
            script::parse(&src).with_context(|| format!("Failed to parse GRUB config {config}"))?;
        self.exec_top(&cmds)?;
        if self.halted {
            return Ok(0);
        }
        match old_file {
            Some(v) => self.set("config_file", &v)?,
            None => self.unset("config_file")?,
        }
        match old_dir {
            Some(v) => self.set("config_directory", &v)?,
            None => self.unset("config_directory")?,
        }
        Ok(0)
    }

    fn entry_number(&self, menu: &[MenuEntry], var: &str) -> Option<usize> {
        let val = self.get(var)?;
        match strtoul(val) {
            Some(n) => Some(n as usize),
            None => menu
                .iter()
                .position(|e| menuentry_eq(&e.title, val) || menuentry_eq(&e.id, val)),
        }
    }

    /// `grub_show_menu` without user interaction: boot the default entry
    /// once the timeout expires, then try the fallback entries.
    fn show_menu(&mut self, _nested: bool, autobooted: bool) -> Result<()> {
        let menu = self.ctx().menu.clone().unwrap_or_default();
        if menu.is_empty() {
            return Ok(());
        }
        if self.gfxterm && self.get("theme").is_some_and(|t| !t.is_empty()) {
            bail!("GRUB graphical menu themes are not supported");
        }
        match self.get("timeout").and_then(strtoul) {
            Some(_) => {}
            None => warn!("GRUB menu has no timeout; assuming the default entry is chosen"),
        }
        let default = self
            .entry_number(&menu, "default")
            .filter(|&n| n < menu.len())
            .unwrap_or(0);
        debug!(
            "grub: booting menu entry {default}: {}",
            menu[default].title
        );
        self.execute_entry(&menu[default], true)?;
        if self.halted {
            return Ok(());
        }
        let fallbacks: Vec<usize> = self
            .get("fallback")
            .map(|f| {
                split_ws(f)
                    .iter()
                    .filter_map(|n| strtoul(n))
                    .map(|n| n as usize)
                    .collect()
            })
            .unwrap_or_default();
        for n in fallbacks {
            if let Some(e) = menu.get(n) {
                debug!("grub: falling back to menu entry {n}: {}", e.title);
                self.execute_entry(e, true)?;
                if self.halted {
                    return Ok(());
                }
            }
        }
        if !autobooted {
            bail!("no GRUB menu entry booted a kernel");
        }
        Ok(())
    }

    /// `grub_menu_execute_entry`.
    fn execute_entry(&mut self, entry: &MenuEntry, auto_boot: bool) -> Result<()> {
        let chosen = self.get_owned("chosen");
        let default = self.get_owned("default");
        if entry.submenu {
            self.context_open();
            self.ctx().menu = Some(Vec::new());
            if auto_boot {
                self.set("timeout", "0")?;
            }
        }
        let mut id = String::new();
        for c in entry.id.chars() {
            if c == '>' {
                id.push('>');
            }
            id.push(c);
        }
        let new_chosen = match &chosen {
            Some(c) => format!("{c}>{id}"),
            None => id,
        };
        self.set_exported("chosen", &new_chosen)?;
        let rest = default.as_deref().and_then(|d| {
            let b = d.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'>' && b.get(i + 1) == Some(&b'>') {
                    i += 2;
                    continue;
                }
                if b[i] == b'>' {
                    return Some(&d[i + 1..]);
                }
                i += 1;
            }
            None
        });
        match rest.filter(|r| !r.is_empty()).map(str::to_owned) {
            Some(r) => self.set("default", &r)?,
            None => self.unset("default")?,
        }
        self.execute_new_scope(&entry.source, &entry.args)?;
        if self.halted {
            return Ok(());
        }
        if self.kernel.is_some() {
            self.halted = true;
            return Ok(());
        }
        if entry.submenu {
            self.show_menu(true, auto_boot)?;
            self.context_close();
            if self.halted {
                return Ok(());
            }
        }
        match chosen {
            Some(v) => self.set("chosen", &v)?,
            None => self.unset("chosen")?,
        }
        match default {
            Some(v) => self.set("default", &v)?,
            None => self.unset("default")?,
        }
        self.unset("timeout")
    }

    fn execute_new_scope(&mut self, source: &str, args: &[String]) -> Result<Flow> {
        self.enter()?;
        self.scopes.push(args.to_vec());
        let r = script::parse(source)
            .context("Failed to parse GRUB script")
            .and_then(|cmds| self.exec_top(&cmds));
        self.scopes.pop();
        self.depth -= 1;
        Ok(match r? {
            Flow::Halt => Flow::Halt,
            _ => Flow::Next,
        })
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            bail!("GRUB script recursion is too deep");
        }
        Ok(())
    }

    // ---- script execution -------------------------------------------------

    fn define_functions(&mut self, cmd: &Cmd) {
        match cmd {
            Cmd::Function { name, body } => {
                for c in body {
                    self.define_functions(c);
                }
                self.functions.insert(name.clone(), Rc::new(body.clone()));
            }
            Cmd::If {
                branches,
                otherwise,
            } => {
                for (c, b) in branches {
                    c.iter().chain(b).for_each(|x| self.define_functions(x));
                }
                otherwise
                    .iter()
                    .flatten()
                    .for_each(|x| self.define_functions(x));
            }
            Cmd::For { body, .. } => body.iter().for_each(|x| self.define_functions(x)),
            Cmd::While { cond, body, .. } => cond
                .iter()
                .chain(body)
                .for_each(|x| self.define_functions(x)),
            Cmd::Simple(_) => {}
        }
    }

    /// Execute commands one at a time, the way GRUB parses and runs a file.
    fn exec_top(&mut self, cmds: &[Cmd]) -> Result<Flow> {
        for cmd in cmds {
            self.define_functions(cmd);
            match self.exec(cmd)? {
                Flow::Next => {}
                f => return Ok(f),
            }
        }
        Ok(Flow::Next)
    }

    fn exec_list(&mut self, cmds: &[Cmd]) -> Result<Flow> {
        for cmd in cmds {
            match self.exec(cmd)? {
                Flow::Next => {}
                f => return Ok(f),
            }
        }
        Ok(Flow::Next)
    }

    fn exec_loop_body(&mut self, body: &[Cmd]) -> Result<Option<Flow>> {
        Ok(match self.exec_list(body)? {
            Flow::Next => None,
            Flow::Break(n) if n > 1 => Some(Flow::Break(n - 1)),
            Flow::Break(_) => Some(Flow::Next),
            Flow::Continue(n) if n > 1 => Some(Flow::Continue(n - 1)),
            Flow::Continue(_) => None,
            f => Some(f),
        })
    }

    fn exec(&mut self, cmd: &Cmd) -> Result<Flow> {
        match cmd {
            Cmd::Simple(args) => self.exec_simple(args, true),
            Cmd::If {
                branches,
                otherwise,
            } => {
                for (cond, body) in branches {
                    match self.exec_list(cond)? {
                        Flow::Next => {}
                        f => return Ok(f),
                    }
                    if self.get("?") == Some("0") {
                        return self.exec_list(body);
                    }
                }
                match otherwise {
                    Some(body) => self.exec_list(body),
                    None => Ok(Flow::Next),
                }
            }
            Cmd::For { var, words, body } => {
                let args: Vec<Arg> = words.iter().cloned().map(Arg::Word).collect();
                let items = self.expand(&args)?;
                self.loops += 1;
                let mut out = Flow::Next;
                for item in items {
                    self.set(var, &item)?;
                    if let Some(f) = self.exec_loop_body(body)? {
                        out = f;
                        break;
                    }
                }
                self.loops -= 1;
                Ok(out)
            }
            Cmd::While { until, cond, body } => {
                self.loops += 1;
                let mut out = Flow::Next;
                loop {
                    self.tick()?;
                    match self.exec_list(cond)? {
                        Flow::Next => {}
                        f => {
                            out = f;
                            break;
                        }
                    }
                    if (self.last_ret == 0) == *until {
                        break;
                    }
                    if let Some(f) = self.exec_loop_body(body)? {
                        out = f;
                        break;
                    }
                }
                self.loops -= 1;
                Ok(out)
            }
            Cmd::Function { .. } => Ok(Flow::Next),
        }
    }

    fn tick(&mut self) -> Result<()> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            bail!("GRUB script did not finish after {MAX_STEPS} steps");
        }
        Ok(())
    }

    /// Values a variable reference expands to (`grub_script_env_get`).
    fn var_values(&self, name: &str, quoted: bool) -> Vec<String> {
        let special =
            name.starts_with(|c: char| c.is_ascii_digit()) || matches!(name, "#" | "*" | "@");
        if !special {
            return match self.get(name).filter(|v| !v.is_empty()) {
                Some(v) if quoted => vec![v.to_string()],
                Some(v) => split_ws(v),
                None => Vec::new(),
            };
        }
        let Some(args) = self.scopes.last() else {
            return vec![String::new()];
        };
        let split_all = || args.iter().flat_map(|a| split_ws(a)).collect();
        match name {
            "#" => vec![args.len().to_string()],
            "*" if quoted => vec![args.join(" ")],
            "@" if quoted => args.clone(),
            "*" | "@" => split_all(),
            _ => match name.parse::<usize>() {
                Ok(n) if n >= 1 && n <= args.len() => {
                    if quoted {
                        vec![args[n - 1].clone()]
                    } else {
                        split_ws(&args[n - 1])
                    }
                }
                _ => Vec::new(),
            },
        }
    }

    /// `grub_script_arglist_to_argv`.
    fn expand(&self, args: &[Arg]) -> Result<Vec<String>> {
        let mut out: Vec<Option<String>> = Vec::new();
        let mut glob: Vec<bool> = Vec::new();
        fn next(out: &mut Vec<Option<String>>, glob: &mut Vec<bool>) {
            if !matches!(out.last(), Some(None)) {
                out.push(None);
                glob.push(false);
            }
        }
        fn append(out: &mut [Option<String>], s: &str) {
            out.last_mut()
                .unwrap()
                .get_or_insert_with(String::new)
                .push_str(s);
        }
        let has_glob = |s: &str| s.contains(['*', '?']);
        for arg in args {
            next(&mut out, &mut glob);
            match arg {
                Arg::Block { raw, .. } => append(&mut out, &format!("{{{raw}}}")),
                Arg::Word(word) => {
                    for seg in word {
                        match seg {
                            Seg::Text(t) => {
                                if !t.is_empty() {
                                    append(&mut out, t);
                                    *glob.last_mut().unwrap() |= has_glob(t);
                                }
                            }
                            Seg::Quoted(t) => append(&mut out, t),
                            Seg::Var { name, quoted } => {
                                for (i, v) in self.var_values(name, *quoted).iter().enumerate() {
                                    if i != 0 {
                                        next(&mut out, &mut glob);
                                    }
                                    append(&mut out, v);
                                    *glob.last_mut().unwrap() |= !quoted && has_glob(v);
                                }
                            }
                        }
                    }
                }
            }
        }
        if matches!(out.last(), Some(None)) {
            out.pop();
        }
        let out: Vec<String> = out.into_iter().map(Option::unwrap_or_default).collect();
        for (a, g) in out.iter().zip(&glob) {
            if *g && a.starts_with(['/', '(', '*']) {
                bail!("GRUB wildcard expansion is not supported: {a}");
            }
        }
        Ok(out)
    }

    fn is_command(&self, name: &str) -> bool {
        const BUILTIN: &[&str] = &[
            "set",
            "unset",
            "export",
            "true",
            "false",
            "[",
            "test",
            "insmod",
            "search",
            "search.file",
            "search.fs_uuid",
            "search.fs_label",
            "source",
            ".",
            "configfile",
            "normal",
            "eval",
            "linux",
            "linuxefi",
            "initrd",
            "initrdefi",
            "boot",
            "menuentry",
            "submenu",
            "setparams",
            "return",
            "shift",
            "break",
            "continue",
            "load_env",
            "save_env",
            "loadfont",
            "keystatus",
            "terminal_input",
            "terminal_output",
        ];
        BUILTIN.contains(&name)
            || NOOP_COMMANDS.contains(&name)
            || UNSUPPORTED_COMMANDS.contains(&name)
            || self.dyncmds.contains_key(name)
    }

    /// `grub_script_execute_cmdline`.
    fn exec_simple(&mut self, args: &[Arg], measure: bool) -> Result<Flow> {
        self.tick()?;
        let argv = self.expand(args)?;
        if argv.is_empty() {
            return Ok(Flow::Next);
        }
        if measure {
            self.events.push(GrubEvent::Command(argv.join(" ")));
        }
        let (invert, name, rest) = if argv[0] == "!" {
            if argv.len() < 2 {
                self.set_status(ERR_BAD_ARGUMENT);
                return Ok(Flow::Next);
            }
            (true, argv[1].as_str(), &argv[2..])
        } else {
            (false, argv[0].as_str(), &argv[1..])
        };
        let (ret, flow) = if self.is_command(name) {
            match self
                .dyncmds
                .get(name)
                .filter(|m| !self.loaded.contains(*m))
                .cloned()
            {
                Some(module) => match self.load_module(&module)? {
                    0 => self.command(name, rest)?,
                    err => (err, Flow::Next),
                },
                None => self.command(name, rest)?,
            }
        } else if let Some(body) = self.functions.get(name).cloned() {
            self.call_function(&body, rest)?
        } else {
            if let Some((var, val)) = name.split_once('=') {
                self.set(var, val)?;
            } else {
                debug!("grub: ignoring unknown command `{name}`");
            }
            self.set_status(0);
            return Ok(Flow::Next);
        };
        let ret = match (invert, ret) {
            (false, r) => r,
            (true, ERR_TEST_FAILURE) => 0,
            (true, 0) => ERR_TEST_FAILURE,
            (true, _) => 0,
        };
        self.set_status(ret);
        Ok(flow)
    }

    fn call_function(&mut self, body: &[Cmd], args: &[String]) -> Result<(i32, Flow)> {
        self.enter()?;
        self.scopes.push(args.to_vec());
        let loops = std::mem::replace(&mut self.loops, 0);
        let r = self.exec_list(body);
        self.loops = loops;
        self.scopes.pop();
        self.depth -= 1;
        Ok(match r? {
            Flow::Halt => (0, Flow::Halt),
            _ => (self.last_ret, Flow::Next),
        })
    }

    // ---- commands ---------------------------------------------------------

    fn command(&mut self, name: &str, args: &[String]) -> Result<(i32, Flow)> {
        let ok = |r: i32| Ok((r, Flow::Next));
        match name {
            "set" => match args.first() {
                None => ok(0),
                Some(a) => match a.split_once('=') {
                    Some((n, v)) => {
                        self.set(n, v)?;
                        ok(0)
                    }
                    None => ok(ERR_BAD_ARGUMENT),
                },
            },
            "unset" => {
                for a in args {
                    self.unset(a)?;
                }
                ok(0)
            }
            "export" => {
                for a in args {
                    self.export(a)?;
                }
                ok(0)
            }
            "true" => ok(0),
            "false" => ok(ERR_TEST_FAILURE),
            "[" | "test" => {
                let mut args = args;
                if args.last().map(String::as_str) == Some("]") {
                    args = &args[..args.len() - 1];
                }
                let mut pos = 0;
                let r = self.test_parse(args, &mut pos)?;
                ok(if r { 0 } else { ERR_TEST_FAILURE })
            }
            "insmod" => match args.first() {
                None => ok(ERR_BAD_ARGUMENT),
                Some(m) if m.starts_with(['/', '(', '+']) => ok(self.load_module_file(m)?),
                Some(m) => ok(self.load_module(m)?),
            },
            "search" => ok(self.cmd_search(args)?),
            "search.file" | "search.fs_uuid" | "search.fs_label" => {
                let kind = match name {
                    "search.file" => SearchKind::File,
                    "search.fs_uuid" => SearchKind::FsUuid,
                    _ => SearchKind::Label,
                };
                match args.first() {
                    None => ok(ERR_BAD_ARGUMENT),
                    Some(key) => {
                        let hints = args.get(2..).unwrap_or_default().to_vec();
                        ok(self.search(kind, key, args.get(1).map(String::as_str), &hints)?)
                    }
                }
            }
            "source" | "." => {
                if args.len() != 1 {
                    return ok(ERR_BAD_ARGUMENT);
                }
                let r = self.normal_execute(Some(&args[0]), true, true)?;
                ok(r)
            }
            "configfile" => {
                if args.len() != 1 {
                    return ok(ERR_BAD_ARGUMENT);
                }
                self.context_open();
                let r = self.normal_execute(Some(&args[0]), true, false);
                if !self.halted {
                    self.context_close();
                }
                ok(r?)
            }
            "normal" => Ok((0, self.cmd_normal(args)?)),
            "eval" => {
                let src = args.join(" ");
                let cmds = script::parse(&src).context("Failed to parse GRUB eval")?;
                let flow = self.exec_top(&cmds)?;
                Ok((self.last_ret, flow))
            }
            "linux" | "linuxefi" => {
                let Some(path) = args.first() else {
                    return ok(ERR_BAD_ARGUMENT);
                };
                self.initrds.clear();
                if self.open(path, true)?.is_none() {
                    self.kernel = None;
                    return ok(ERR_FILE_NOT_FOUND);
                }
                let cmdline = loader_cmdline(args);
                self.events.push(GrubEvent::KernelCmdline(cmdline.clone()));
                self.kernel = Some((path.clone(), cmdline));
                ok(0)
            }
            "initrd" | "initrdefi" => {
                if args.is_empty() || self.kernel.is_none() {
                    return ok(ERR_BAD_ARGUMENT);
                }
                self.initrds.clear();
                let mut names = Vec::new();
                for a in args {
                    let file = match a.strip_prefix("newc:") {
                        Some(r) => r.split_once(':').map(|(_, f)| f).unwrap_or(r),
                        None => a,
                    };
                    if self.open(file, true)?.is_none() {
                        return ok(ERR_FILE_NOT_FOUND);
                    }
                    names.push(file.to_string());
                }
                self.initrds = names;
                ok(0)
            }
            "boot" => {
                if self.kernel.is_some() {
                    self.halted = true;
                    return Ok((0, Flow::Halt));
                }
                ok(ERR_NO_KERNEL)
            }
            "menuentry" | "submenu" => ok(self.cmd_menuentry(args, name == "submenu")?),
            "setparams" => match self.scopes.last_mut() {
                Some(s) => {
                    *s = args.to_vec();
                    ok(0)
                }
                None => ok(ERR_BAD_ARGUMENT),
            },
            "return" => {
                if self.scopes.is_empty() || args.len() > 1 {
                    return ok(ERR_BAD_ARGUMENT);
                }
                let r = match args.first() {
                    None => self.get("?").and_then(strtoul).unwrap_or(0) as i32,
                    Some(a) => match a.parse::<i32>() {
                        Ok(n) => n,
                        Err(_) => return ok(ERR_BAD_ARGUMENT),
                    },
                };
                Ok((r, Flow::Return))
            }
            "shift" => {
                let n = args
                    .first()
                    .map(|a| strtoul(a).unwrap_or(0) as usize)
                    .unwrap_or(1);
                match self.scopes.last_mut() {
                    Some(s) if n <= s.len() => {
                        s.drain(..n);
                        ok(0)
                    }
                    _ => ok(ERR_BAD_ARGUMENT),
                }
            }
            "break" | "continue" => {
                let n = args
                    .first()
                    .map(|a| strtoul(a).unwrap_or(0) as usize)
                    .unwrap_or(1);
                if n == 0 {
                    return ok(ERR_BAD_ARGUMENT);
                }
                let n = n.min(self.loops);
                if n == 0 {
                    return ok(0);
                }
                Ok((
                    0,
                    if name == "break" {
                        Flow::Break(n)
                    } else {
                        Flow::Continue(n)
                    },
                ))
            }
            "load_env" => ok(self.cmd_load_env(args)?),
            "save_env" => ok(self.cmd_save_env(args)?),
            "loadfont" => {
                if args.is_empty() {
                    return ok(ERR_BAD_ARGUMENT);
                }
                for a in args {
                    let file = if a.starts_with(['(', '/', '+']) {
                        a.clone()
                    } else {
                        match self.prefix() {
                            Some(p) => format!("{p}/fonts/{a}.pf2"),
                            None => return ok(ERR_FILE_NOT_FOUND),
                        }
                    };
                    if self.open(&file, true)?.is_none() {
                        return ok(ERR_BAD_FONT);
                    }
                }
                ok(0)
            }
            "keystatus" => ok(if args.is_empty() { 0 } else { ERR_TEST_FAILURE }),
            "terminal_input" | "terminal_output" => {
                let kind = if name == "terminal_input" { "i" } else { "o" };
                for a in args.iter().filter(|a| !a.starts_with("--")) {
                    if kind == "o" && a == "gfxterm" {
                        self.gfxterm = true;
                    }
                    let key = format!("{kind}{a}");
                    let module = self.terminal_mods.iter().find_map(|(n, m)| {
                        let hit = match n.strip_suffix('*') {
                            Some(p) => key.starts_with(p),
                            None => *n == key,
                        };
                        hit.then(|| m.clone())
                    });
                    if let Some(m) = module {
                        let r = self.load_module(&m)?;
                        if r != 0 {
                            return ok(r);
                        }
                    }
                }
                ok(0)
            }
            _ if UNSUPPORTED_COMMANDS.contains(&name) => {
                bail!("GRUB command `{name}` is not supported by the measurement replay")
            }
            _ => {
                if !NOOP_COMMANDS.contains(&name) {
                    debug!("grub: command `{name}` has no modelled effect");
                }
                ok(0)
            }
        }
    }

    fn test_parse(&mut self, args: &[String], pos: &mut usize) -> Result<bool> {
        let (mut and, mut or, mut invert) = (true, false, false);
        let update = |v: bool, and: &mut bool, invert: &mut bool| {
            *and = *and && (v ^ *invert);
            *invert = false;
        };
        while *pos < args.len() {
            let a = |i: usize| args[*pos + i].as_str();
            if *pos + 2 < args.len() {
                let (l, op, r) = (a(0), a(1), a(2));
                let num = |f: fn(i64, i64) -> bool| f(strtosl(l), strtosl(r));
                let v = match op {
                    "=" | "==" => Some(l == r),
                    "!=" => Some(l != r),
                    "<" => Some(l < r),
                    "<=" => Some(l <= r),
                    ">" => Some(l > r),
                    ">=" => Some(l >= r),
                    "-eq" => Some(num(|x, y| x == y)),
                    "-ge" => Some(num(|x, y| x >= y)),
                    "-gt" => Some(num(|x, y| x > y)),
                    "-le" => Some(num(|x, y| x <= y)),
                    "-lt" => Some(num(|x, y| x < y)),
                    "-ne" => Some(num(|x, y| x != y)),
                    "-pgt" | "-plt" => {
                        let (lb, rb) = (l.as_bytes(), r.as_bytes());
                        let mut i = lb.iter().zip(rb).take_while(|(x, y)| x == y).count();
                        i = i.saturating_sub(1);
                        while i > 0 && lb.get(i).is_some_and(u8::is_ascii_digit) {
                            i -= 1;
                        }
                        i += 1;
                        let x = strtoul(l.get(i..).unwrap_or("")).unwrap_or(0);
                        let y = strtoul(r.get(i..).unwrap_or("")).unwrap_or(0);
                        Some(if op == "-pgt" { x > y } else { x < y })
                    }
                    _ if op.starts_with("-nt") || op.starts_with("-ot") => {
                        bail!("GRUB test `{op}` is not supported")
                    }
                    _ => None,
                };
                if let Some(v) = v {
                    update(v, &mut and, &mut invert);
                    *pos += 3;
                    continue;
                }
            }
            if *pos + 1 < args.len() {
                let (op, f) = (a(0), args[*pos + 1].clone());
                let v = match op {
                    "-d" => Some(self.stat(&f)? == Some(Kind::Dir)),
                    "-e" => Some(self.stat(&f)?.is_some()),
                    "-f" => Some(self.stat(&f)? == Some(Kind::File)),
                    "-s" => Some(self.open(&f, true)?.is_some_and(|d| !d.is_empty())),
                    "-n" => Some(!f.is_empty()),
                    "-z" => Some(f.is_empty()),
                    _ => None,
                };
                if let Some(v) = v {
                    update(v, &mut and, &mut invert);
                    *pos += 2;
                    continue;
                }
            }
            match a(0) {
                ")" => {
                    *pos += 1;
                    return Ok(or || and);
                }
                "(" => {
                    *pos += 1;
                    let v = self.test_parse(args, pos)?;
                    update(v, &mut and, &mut invert);
                }
                "!" => {
                    invert = !invert;
                    *pos += 1;
                }
                "-a" => *pos += 1,
                "-o" => {
                    or = or || and;
                    and = true;
                    *pos += 1;
                }
                s => {
                    let v = !s.is_empty();
                    update(v, &mut and, &mut invert);
                    *pos += 1;
                }
            }
        }
        Ok(or || and)
    }

    fn cmd_menuentry(&mut self, args: &[String], submenu: bool) -> Result<i32> {
        use OptKind::*;
        const SPECS: &[Opt] = &[
            opt("class", None, Value),
            opt("users", None, Value),
            opt("hotkey", None, Value),
            opt("source", None, Value),
            opt("id", None, Value),
            opt("unrestricted", None, Flag),
        ];
        let Some((opts, mut pos)) = parse_opts(args, SPECS, false) else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        if opts.contains_key("source") {
            bail!("GRUB `menuentry --source` is not supported");
        }
        let Some(block) = pos.pop().filter(|b| b.starts_with('{') && b.ends_with('}')) else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        let Some(title) = pos.first().cloned() else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        let mut source = String::from("setparams");
        for a in &pos {
            source.push_str(" '");
            source.push_str(&a.replace('\'', "'\\''"));
            source.push('\'');
        }
        source.push('\n');
        source.push_str(&block[1..block.len() - 1]);
        let entry = MenuEntry {
            id: opt_value(&opts, "id").unwrap_or_else(|| title.clone()),
            title,
            args: pos,
            source,
            submenu,
        };
        match self.ctx().menu.as_mut() {
            Some(menu) => {
                menu.push(entry);
                Ok(0)
            }
            None => Ok(ERR_MENU),
        }
    }

    fn cmd_search(&mut self, args: &[String]) -> Result<i32> {
        use OptKind::*;
        const SPECS: &[Opt] = &[
            opt("file", Some('f'), Flag),
            opt("label", Some('l'), Flag),
            opt("fs-uuid", Some('u'), Flag),
            opt("set", Some('s'), OptValue),
            opt("no-floppy", Some('n'), Flag),
            opt("hint", Some('h'), Value),
            opt("hint-ieee1275", None, Value),
            opt("hint-bios", None, Value),
            opt("hint-baremetal", None, Value),
            opt("hint-efi", None, Value),
            opt("hint-arc", None, Value),
        ];
        let Some((opts, pos)) = parse_opts(args, SPECS, true) else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        let mut hints = opt_values(&opts, "hint");
        hints.extend(opt_values(&opts, "hint-efi"));
        hints.extend(opt_values(&opts, "hint-baremetal"));
        let set = opts.get("set").map(|v| v.last().cloned().flatten());
        let mut var = set
            .as_ref()
            .map(|v| v.clone().unwrap_or_else(|| "root".into()));
        let key = match pos.iter().find(|a| !a.starts_with("--hint-")) {
            Some(k) => k.clone(),
            None => match set.flatten() {
                Some(k) => {
                    var = Some("root".into());
                    k
                }
                None => return Ok(ERR_BAD_ARGUMENT),
            },
        };
        let kind = if opts.contains_key("label") {
            SearchKind::Label
        } else if opts.contains_key("fs-uuid") {
            SearchKind::FsUuid
        } else if opts.contains_key("file") {
            SearchKind::File
        } else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        self.search(kind, &key, var.as_deref(), &hints)
    }

    /// `FUNC_NAME` in `commands/search.c`.
    fn search(
        &mut self,
        kind: SearchKind,
        key: &str,
        var: Option<&str>,
        hints: &[String],
    ) -> Result<i32> {
        let mut count = 0;
        if var.is_some() {
            let saved = self.autoload_enabled;
            self.autoload_enabled = false;
            let r = self.search_try(kind, key, var, hints, &mut count);
            self.autoload_enabled = saved;
            r?;
            if count == 0 {
                self.search_try(kind, key, var, hints, &mut count)?;
            }
        } else {
            self.search_try(kind, key, var, hints, &mut count)?;
        }
        Ok(if count == 0 { ERR_FILE_NOT_FOUND } else { 0 })
    }

    fn search_try(
        &mut self,
        kind: SearchKind,
        key: &str,
        var: Option<&str>,
        hints: &[String],
        count: &mut usize,
    ) -> Result<()> {
        let cached = self
            .search_cache
            .iter()
            .position(|(k, ck, _)| *k == kind && Self::key_eq(kind, ck, key));
        if let Some(i) = cached {
            let dev = self.search_cache[i].2.clone();
            if self.search_device(kind, key, var, &dev, true, count)? {
                return Ok(());
            }
            if *count == 0 {
                self.search_cache.remove(i);
            }
        }
        for hint in hints.iter().filter(|h| !h.is_empty()) {
            let (dev, parts) = match hint.strip_suffix(',') {
                Some(d) => (d, true),
                None => (hint.as_str(), false),
            };
            if self.search_device(kind, key, var, dev, false, count)? {
                return Ok(());
            }
            if parts && dev == "hd0" {
                for p in self.disk.partitions()? {
                    if self.search_device(kind, key, var, &format!("hd0,gpt{p}"), false, count)? {
                        return Ok(());
                    }
                }
            }
        }
        // grub_device_iterate: memdisk registers after efidisk and is listed
        // first; partitions of a disk are visited in reverse order.
        let mut devices = Vec::new();
        if self.image.memdisk.is_some() {
            devices.push("memdisk".to_string());
        }
        devices.push("hd0".to_string());
        let mut parts = self.disk.partitions()?;
        parts.reverse();
        devices.extend(parts.iter().map(|p| format!("hd0,gpt{p}")));
        for dev in devices {
            if self.search_device(kind, key, var, &dev, false, count)? {
                return Ok(());
            }
        }
        Ok(())
    }

    fn key_eq(kind: SearchKind, a: &str, b: &str) -> bool {
        match kind {
            SearchKind::FsUuid => a.eq_ignore_ascii_case(b),
            _ => a == b,
        }
    }

    /// `iterate_device` in `commands/search.c`; true stops the iteration.
    fn search_device(
        &mut self,
        kind: SearchKind,
        key: &str,
        var: Option<&str>,
        name: &str,
        is_cache: bool,
        count: &mut usize,
    ) -> Result<bool> {
        let found = match kind {
            SearchKind::File => self.open(&format!("({name}){key}"), true)?.is_some(),
            _ => match parse_dev(name) {
                Some(dev) if self.probe(&dev)? => {
                    let id = match (&dev, kind) {
                        (Dev::Part(n), SearchKind::FsUuid) => self.disk.fs_uuid(*n)?,
                        (Dev::Part(n), _) => self.disk.fs_label(*n)?,
                        _ => None,
                    };
                    id.is_some_and(|id| Self::key_eq(kind, &id, key))
                }
                _ => false,
            },
        };
        if !is_cache && found && *count == 0 {
            self.search_cache
                .insert(0, (kind, key.to_string(), name.to_string()));
        }
        if found {
            *count += 1;
            if let Some(var) = var {
                self.set(var, name)?;
            }
        }
        Ok(found && var.is_some())
    }

    fn envblk_name(&self, opts: &Opts) -> Option<String> {
        opt_value(opts, "file").or_else(|| self.prefix().map(|p| format!("{p}/grubenv")))
    }

    fn cmd_load_env(&mut self, args: &[String]) -> Result<i32> {
        use OptKind::*;
        const SPECS: &[Opt] = &[
            opt("file", Some('f'), Value),
            opt("skip-sig", Some('s'), Flag),
        ];
        let Some((opts, whitelist)) = parse_opts(args, SPECS, false) else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        let Some(file) = self.envblk_name(&opts) else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Some(data) = self.open(&file, !opts.contains_key("skip-sig"))? else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Some(entries) = parse_envblk(&data) else {
            return Ok(ERR_BAD_FILE_TYPE);
        };
        for (k, v) in entries {
            if whitelist.is_empty() || whitelist.contains(&k) {
                self.set(&k, &v)?;
            }
        }
        Ok(0)
    }

    fn cmd_save_env(&mut self, args: &[String]) -> Result<i32> {
        use OptKind::*;
        const SPECS: &[Opt] = &[opt("file", Some('f'), Value)];
        let Some((opts, names)) = parse_opts(args, SPECS, false) else {
            return Ok(ERR_BAD_ARGUMENT);
        };
        if names.is_empty() {
            return Ok(ERR_BAD_ARGUMENT);
        }
        let Some(file) = self.envblk_name(&opts) else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Some((Dev::Part(n), path)) = self.resolve(&file) else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Some(data) = self.open(&file, false)? else {
            return Ok(ERR_FILE_NOT_FOUND);
        };
        let Some(mut entries) = parse_envblk(&data) else {
            return Ok(ERR_BAD_FILE_TYPE);
        };
        for name in &names {
            entries.retain(|(k, _)| k != name);
            if let Some(v) = self.get(name) {
                entries.push((name.clone(), v.to_string()));
            }
        }
        let mut out = String::from(GRUBENV_HEADER);
        for (k, v) in &entries {
            out.push_str(k);
            out.push('=');
            for c in v.chars() {
                if c == '\\' || c == '\n' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('\n');
        }
        if out.len() > data.len() {
            return Ok(ERR_BAD_ARGUMENT);
        }
        let mut out = out.into_bytes();
        out.resize(data.len(), b'#');
        self.overlay.insert((n, normalize(&path)), out);
        Ok(0)
    }
}

/// Parse a grubenv block; `None` if the signature is wrong.
fn parse_envblk(data: &[u8]) -> Option<Vec<(String, String)>> {
    let text = String::from_utf8_lossy(data);
    let body = text.strip_prefix(GRUBENV_HEADER)?;
    let mut out = Vec::new();
    let mut chars = body.chars().peekable();
    // One entry or comment line per iteration.
    while let Some(&c) = chars.peek() {
        if c == '#' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        let mut name = String::new();
        let mut value = String::new();
        let mut in_value = false;
        while let Some(c) = chars.next() {
            match c {
                '\n' => break,
                '\\' if in_value => {
                    if let Some(n) = chars.next() {
                        value.push(n);
                    }
                }
                '=' if !in_value => in_value = true,
                c if in_value => value.push(c),
                c => name.push(c),
            }
        }
        if in_value && !name.is_empty() {
            out.push((name, value));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_match_grub() {
        assert_eq!(strtoul("1>2"), Some(1));
        assert_eq!(strtoul("0x10"), Some(16));
        assert_eq!(strtoul("gnulinux"), None);
        assert!(menuentry_eq("gnulinux-simple", "gnulinux-simple>sub"));
        assert!(!menuentry_eq("a", "ab"));
        assert!(menuentry_eq("a>b", "a>>b"));
        assert_eq!(
            loader_cmdline(&["/vmlinuz".into(), "a=\"x y\"".into(), "ro".into()]),
            "/vmlinuz \"a=\\\"x y\\\"\" ro"
        );
        let env = format!("{GRUBENV_HEADER}saved_entry=a\\\\b\nx=1\n####");
        assert_eq!(
            parse_envblk(env.as_bytes()).unwrap(),
            vec![
                ("saved_entry".into(), "a\\b".into()),
                ("x".into(), "1".into())
            ]
        );
    }

    #[derive(Default)]
    struct MemDisk {
        files: HashMap<(u32, String), Vec<u8>>,
        uuids: HashMap<u32, String>,
    }

    impl GrubDisk for MemDisk {
        fn partitions(&mut self) -> Result<Vec<u32>> {
            Ok(vec![1, 2])
        }
        fn fs_module(&mut self, part: u32) -> Result<Option<String>> {
            Ok(Some(if part == 1 { "fat" } else { "ext2" }.into()))
        }
        fn stat(&mut self, part: u32, path: &str) -> Result<Option<Kind>> {
            if self.files.contains_key(&(part, path.to_string())) {
                return Ok(Some(Kind::File));
            }
            let dir = format!("{path}/");
            let is_dir = self
                .files
                .keys()
                .any(|(p, f)| *p == part && f.starts_with(&dir));
            Ok(is_dir.then_some(Kind::Dir))
        }
        fn read(&mut self, part: u32, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.files.get(&(part, path.to_string())).cloned())
        }
        fn fs_uuid(&mut self, part: u32) -> Result<Option<String>> {
            Ok(self.uuids.get(&part).cloned())
        }
        fn fs_label(&mut self, _part: u32) -> Result<Option<String>> {
            Ok(None)
        }
    }

    /// Replays the veLinux boot whose RTMR2 event log the test data was
    /// reconstructed from (Debian 12 signed grubx64.efi, config in the ESP's
    /// `/EFI/velinux`, `/boot` on the ext4 root partition).
    #[test]
    fn replays_velinux_boot() {
        let mut memdisk = super::super::MemFs::default();
        memdisk.insert_file(
            "/grub.cfg",
            include_bytes!("testdata/velinux/memdisk-grub.cfg").to_vec(),
        );
        let image = GrubImage {
            modules: [
                "normal",
                "search",
                "test",
                "all_video",
                "gzio",
                "part_gpt",
                "ext2",
                "fat",
                "serial",
                "linux",
            ]
            .map(String::from)
            .to_vec(),
            config: Some("normal (memdisk)/grub.cfg\n".into()),
            prefix: Some("/EFI/debian".into()),
            memdisk: Some(memdisk),
        };
        let uuid = "3380322c-4b39-11ef-b6d3-525400123456";
        let mut disk = MemDisk::default();
        disk.uuids.insert(1, "1234-ABCD".into());
        disk.uuids.insert(2, uuid.into());
        let mut add = |part: u32, path: &str, data: &[u8]| {
            disk.files.insert((part, path.to_string()), data.to_vec());
        };
        add(
            1,
            "/EFI/velinux/grub.cfg",
            include_bytes!("testdata/velinux/esp-grub.cfg"),
        );
        add(1, "/EFI/velinux/shimx64.efi", b"shim");
        add(
            2,
            "/boot/grub/grub.cfg",
            include_bytes!("testdata/velinux/grub.cfg"),
        );
        let mut grubenv = GRUBENV_HEADER.as_bytes().to_vec();
        grubenv.resize(1024, b'#');
        add(2, "/boot/grub/grubenv", &grubenv);
        add(
            2,
            "/boot/grub/x86_64-efi/command.lst",
            b"serial: serial\nfwsetup: efifwsetup\n",
        );
        add(2, "/boot/grub/x86_64-efi/fs.lst", b"ext2\nfat\n");
        add(2, "/boot/grub/x86_64-efi/crypto.lst", b"");
        add(
            2,
            "/boot/grub/x86_64-efi/terminal.lst",
            b"iserial: serial\noserial: serial\n",
        );
        let kver = "6.6.63.ve.1u13-1-gb8cfddc466877-amd64";
        add(2, &format!("/boot/vmlinuz-{kver}"), b"kernel");
        add(2, &format!("/boot/initrd.img-{kver}"), b"initrd");

        let boot = simulate(&image, &mut disk, 1, "/EFI/velinux").unwrap();
        let expected: Vec<String> =
            serde_json::from_str(include_str!("testdata/velinux/events.json")).unwrap();
        let actual: Vec<String> = boot.events.iter().map(GrubEvent::description).collect();
        assert_eq!(actual, expected);
        assert_eq!(boot.kernel, format!("/boot/vmlinuz-{kver}"));
        assert_eq!(boot.initrds, vec![format!("/boot/initrd.img-{kver}")]);
        assert!(boot.kernel_cmdline().starts_with(&format!(
            "BOOT_IMAGE=/boot/vmlinuz-{kver} root=UUID={uuid} ro "
        )));
        assert_eq!(
            boot.events[7].digest(),
            measure_sha384(include_bytes!("testdata/velinux/esp-grub.cfg"))
        );
    }
}
