//! Parse QEMU command tokens into the structured [`Grouped`](crate::model::Grouped) model.

use crate::model::{Grouped, Props};
use crate::property::Property;

impl From<&[String]> for Grouped {
    /// Parse a flat token stream directly into the grouped semantic model.
    ///
    /// Heuristic for boolean flags: a flag consumes the next token as its value
    /// only when that token exists and does not itself start with `-`.
    fn from(tokens: &[String]) -> Self {
        let mut out = Self::default();
        let mut i = 0;

        // Leading non-flag token is the executable — skip it.
        if let Some(first) = tokens.first() {
            if !first.starts_with('-') {
                i = 1;
            }
        }

        // Collect (flag, value) pairs, handling stray positional fragments.
        let mut raw_opts: Vec<(String, Option<String>)> = Vec::new();

        while i < tokens.len() {
            let tok = &tokens[i];
            if let Some(flag) = tok.strip_prefix('-') {
                if let Some((f, v)) = flag.split_once('=') {
                    raw_opts.push((f.to_string(), Some(v.to_string())));
                    i += 1;
                    continue;
                }

                let takes_value = tokens
                    .get(i + 1)
                    .map(|n| !n.starts_with('-'))
                    .unwrap_or(false);

                if takes_value {
                    raw_opts.push((flag.to_string(), Some(tokens[i + 1].clone())));
                    i += 2;
                } else {
                    raw_opts.push((flag.to_string(), None));
                    i += 1;
                }
            } else {
                // Stray positional token — append to previous option's value.
                if let Some(prev) = raw_opts.last_mut() {
                    if let Some(ref mut v) = prev.1 {
                        v.push(' ');
                        v.push_str(tok);
                    } else {
                        prev.1 = Some(tok.clone());
                    }
                }
                i += 1;
            }
        }

        // Decode each option into the grouped model.
        for (flag, value) in &raw_opts {
            let props = value.as_deref().map(Property::parse).unwrap_or_default();
            out.decode_option(flag, &props, value.as_deref());
        }

        out
    }
}

impl Grouped {
    /// Decode a single QEMU option into the appropriate section.
    fn decode_option(&mut self, flag: &str, props: &[Property], raw_value: Option<&str>) {
        let scalar = || raw_value.map(str::to_string);

        match flag {
            "machine" | "M" => {
                let mut m = to_map(props, "type");
                if let Some(t) = m.get("type").cloned() {
                    m.insert("type".to_string(), t);
                }
                if let Some(ref mut existing) = self.machine {
                    existing.extend(m);
                } else {
                    self.machine = Some(m);
                }
            }
            "accel" => self.accel = Some(to_map(props, "type")),
            "object" => self.objects.push(to_map(props, "type")),
            "cpu" => self.cpu = Some(to_map(props, "model")),
            "m" => self.memory = Some(to_map(props, "size")),
            "smp" => self.smp = Some(to_map(props, "cpus")),
            "numa" => self.numa.push(to_map(props, "type")),
            "device" => self.devices.push(to_map(props, "driver")),
            "bios" => self.bios = scalar(),
            "fw_cfg" => self.fw_cfg.push(to_map(props, "name")),
            "acpitable" => self.acpitables.push(to_map(props, "file")),
            "global" => self.globals.push(to_map(props, "property")),
            "netdev" => self.netdevs.push(to_map(props, "type")),
            "chardev" => self.chardevs.push(to_map(props, "type")),
            "nodefaults" => self.nodefaults = true,
            "kernel" => self.kernel = scalar(),
            "initrd" => self.initrd = scalar(),
            "append" => self.append = scalar(),
            _ => {}
        }
    }
}

/// Convert a list of sub-properties to a flat `BTreeMap`, assigning the
/// positional (bare) value to `positional_key`.
fn to_map(props: &[Property], positional_key: &str) -> Props {
    let mut m = Props::new();
    for p in props {
        match &p.value {
            Some(v) => {
                m.insert(p.key.clone(), v.clone());
            }
            None => {
                m.insert(positional_key.to_string(), p.key.clone());
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_boolean_flag() {
        let toks = vec![
            "qemu-system-x86_64".to_string(),
            "-enable-kvm".to_string(),
            "-cpu".to_string(),
            "host".to_string(),
        ];
        let g = Grouped::from(toks.as_slice());
        assert!(g.cpu.is_some());
        assert_eq!(g.cpu.as_ref().unwrap().get("model").map(|s| s.as_str()), Some("host"));
    }
}
