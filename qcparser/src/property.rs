//! QEMU option sub-property parsing.
//!
//! A `Property` represents a single `key=value` or bare `key` within a QEMU
//! option value string. Supports classic comma-separated and JSON object formats.
//! 
use serde_json::Value;

/// A single `key=value` (or bare `key`) sub-property of an option value.
#[derive(Debug, Clone, PartialEq)]
pub struct Property {
    pub key: String,
    pub value: Option<String>,
}

impl Property {
    /// Split a QEMU option value into properties.
    ///
    /// Supports two formats:
    /// 1. Classic comma-separated: `a=b,c=d,flag` (with `,,` escaping for literal commas)
    /// 2. JSON object: `{"key":"value","key2":123,...}` (libvirt ≥ 8.x style)
    pub fn parse(value: &str) -> Vec<Self> {
        if value.starts_with('{') {
            return Self::parse_json(value);
        }
        Self::parse_classic(value)
    }

    fn parse_classic(value: &str) -> Vec<Self> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut chars = value.chars().peekable();

        while let Some(c) = chars.next() {
            if c == ',' {
                if chars.peek() == Some(&',') {
                    chars.next();
                    current.push(',');
                } else {
                    parts.push(std::mem::take(&mut current));
                }
            } else {
                current.push(c);
            }
        }
        parts.push(current);

        parts
            .into_iter()
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => Self {
                    key: k.to_string(),
                    value: Some(v.to_string()),
                },
                None => Self {
                    key: p,
                    value: None,
                },
            })
            .collect()
    }

    fn parse_json(value: &str) -> Vec<Self> {
        let Ok(obj) = serde_json::from_str::<Value>(value) else {
            return vec![Self {
                key: value.to_string(),
                value: None,
            }];
        };

        let Some(map) = obj.as_object() else {
            return vec![Self {
                key: value.to_string(),
                value: None,
            }];
        };

        fn scalar_to_string(v: &Value) -> String {
            match v {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                other => other.to_string(),
            }
        }

        let mut props = Vec::new();
        for (k, v) in map {
            if k == "qom-type" {
                props.insert(0, Self { key: scalar_to_string(v), value: None });
                continue;
            }

            match v {
                // Single-element JSON arrays (e.g. libvirt's `"host-nodes":[1]` /
                // `"node-affinity":[1]`) map to a scalar keyval `key=1`. These QEMU
                // properties are parsed as a "uint64 value or range" string, not a
                // keyval list, so `key.0=1` is rejected.
                Value::Array(items) if items.len() == 1 => {
                    props.push(Self {
                        key: k.clone(),
                        value: Some(scalar_to_string(&items[0])),
                    });
                }
                // Multi-element arrays fall back to QEMU keyval list syntax
                // `key.0=v0,key.1=v1`.
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        props.push(Self {
                            key: format!("{k}.{i}"),
                            value: Some(scalar_to_string(item)),
                        });
                    }
                }
                _ => props.push(Self {
                    key: k.clone(),
                    value: Some(scalar_to_string(v)),
                }),
            }
        }

        props
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop<'a>(props: &'a [Property], key: &str) -> Option<&'a str> {
        props
            .iter()
            .find(|p| p.key == key)
            .and_then(|p| p.value.as_deref())
    }

    fn positional(props: &[Property]) -> Option<&str> {
        props
            .iter()
            .find(|p| p.value.is_none())
            .map(|p| p.key.as_str())
    }

    #[test]
    fn split_basic() {
        let p = Property::parse("virtio-net-pci,netdev=n0,bus=pci.1");
        assert_eq!(positional(&p), Some("virtio-net-pci"));
        assert_eq!(prop(&p, "netdev"), Some("n0"));
        assert_eq!(prop(&p, "bus"), Some("pci.1"));
    }

    #[test]
    fn escaped_comma() {
        let p = Property::parse("string=a,,b");
        assert_eq!(prop(&p, "string"), Some("a,b"));
    }

    #[test]
    fn json_object_props() {
        let p = Property::parse(
            r#"{"qom-type":"memory-backend-file","id":"ram0","size":4096,"share":true,"host-nodes":[1]}"#,
        );
        assert_eq!(positional(&p), Some("memory-backend-file"));
        assert_eq!(prop(&p, "id"), Some("ram0"));
        assert_eq!(prop(&p, "size"), Some("4096"));
        assert_eq!(prop(&p, "share"), Some("true"));
        assert_eq!(prop(&p, "host-nodes"), Some("1"));
    }

    #[test]
    fn json_single_element_array_is_scalar() {
        let p = Property::parse(
            r#"{"qom-type":"thread-context","id":"tc0","node-affinity":[1]}"#,
        );
        assert_eq!(positional(&p), Some("thread-context"));
        assert_eq!(prop(&p, "node-affinity"), Some("1"));
    }

    #[test]
    fn json_multi_element_array_expands_to_keyval_list() {
        let p = Property::parse(
            r#"{"qom-type":"thread-context","id":"tc0","node-affinity":[1,2]}"#,
        );
        assert_eq!(prop(&p, "node-affinity.0"), Some("1"));
        assert_eq!(prop(&p, "node-affinity.1"), Some("2"));
    }

    #[test]
    fn json_device_props() {
        let p =
            Property::parse(r#"{"driver":"virtio-net-pci","netdev":"n0","bus":"pci.6","addr":"0x1"}"#);
        assert_eq!(prop(&p, "driver"), Some("virtio-net-pci"));
        assert_eq!(prop(&p, "netdev"), Some("n0"));
    }
}
