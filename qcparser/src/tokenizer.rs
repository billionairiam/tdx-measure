//! Shell-aware tokenizer for QEMU command strings.
//!
//! Supports three input formats, auto-detected:
//!
//! 1. **Raw `/proc/PID/cmdline`** — null-byte separated tokens.
//! 2. **`cmdline | tr '\0' '\n'`** — one token per line (no shell quoting needed).
//! 3. **Shell command** — classic space-separated with quotes, escapes and `\`
//!    line-continuations.
//!
//! JSON object literals (`{...}`) are captured verbatim in all modes.

/// Split a raw command string into tokens, auto-detecting the format.
pub fn tokenize(input: &str) -> Vec<String> {
    // 1. Raw null-separated /proc/PID/cmdline.
    if input.contains('\0') {
        return input
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
    }

    // 2. One-token-per-line (cmdline piped through `tr '\0' '\n'`).
    if is_cmdline_format(input) {
        return input
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
    }

    // 3. Shell-style tokenization.
    tokenize_shell(input)
}

/// Heuristic: the input is cmdline-format if it has ≥3 non-empty lines and
/// lines that start with `-` are bare flags (no whitespace after the flag name).
fn is_cmdline_format(input: &str) -> bool {
    let lines: Vec<&str> = input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if lines.len() < 3 {
        return false;
    }

    // Check that flag-lines are bare (no space = no value on the same line).
    let flag_lines = lines.iter().filter(|l| l.starts_with('-'));
    let bare_flags = flag_lines.clone().filter(|l| !l.contains(' ')).count();
    let total_flags = flag_lines.count();

    // If all (or nearly all) flag lines are bare → cmdline format.
    total_flags > 0 && bare_flags == total_flags
}

/// Shell-aware tokenization: quotes, escapes, line continuations, JSON `{…}`.
fn tokenize_shell(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('\n') => {
                    chars.next();
                }
                Some('\r') => {
                    chars.next();
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
                Some(&next) => {
                    chars.next();
                    current.push(next);
                    has_token = true;
                }
                None => {
                    current.push('\\');
                    has_token = true;
                }
            },
            '\'' => {
                has_token = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    current.push(q);
                }
            }
            '"' => {
                has_token = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(&next) = chars.peek() {
                                chars.next();
                                current.push(next);
                            }
                        }
                        _ => current.push(q),
                    }
                }
            }
            '{' => {
                has_token = true;
                current.push('{');
                let mut depth: u32 = 1;
                while depth > 0 {
                    match chars.next() {
                        Some('{') => {
                            depth += 1;
                            current.push('{');
                        }
                        Some('}') => {
                            depth -= 1;
                            current.push('}');
                        }
                        Some(ch) => current.push(ch),
                        None => break,
                    }
                }
            }
            c if c.is_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            _ => {
                current.push(c);
                has_token = true;
            }
        }
    }

    if has_token {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_split() {
        assert_eq!(tokenize("a b  c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn line_continuation() {
        let cmd = "qemu \\\n -m 4G";
        assert_eq!(tokenize(cmd), vec!["qemu", "-m", "4G"]);
    }

    #[test]
    fn quotes() {
        assert_eq!(
            tokenize("-append 'console=ttyS0 root=/dev/sda'"),
            vec!["-append", "console=ttyS0 root=/dev/sda"]
        );
    }

    #[test]
    fn double_quotes_with_escape() {
        assert_eq!(tokenize("\"a\\\"b\""), vec!["a\"b"]);
    }

    #[test]
    fn json_object_literal() {
        let input = r#"-object {"qom-type":"secret","id":"key0","file":"/tmp/k"} -m 4G"#;
        let tokens = tokenize(input);
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], "-object");
        assert_eq!(
            tokens[1],
            r#"{"qom-type":"secret","id":"key0","file":"/tmp/k"}"#
        );
        assert_eq!(tokens[2], "-m");
        assert_eq!(tokens[3], "4G");
    }

    #[test]
    fn json_with_nested_array() {
        let input = r#"-object {"qom-type":"memory-backend-file","host-nodes":[1],"size":4096}"#;
        let tokens = tokenize(input);
        assert_eq!(tokens.len(), 2);
        assert!(tokens[1].contains("[1]"));
        assert!(tokens[1].starts_with('{'));
        assert!(tokens[1].ends_with('}'));
    }

    #[test]
    fn cmdline_format_newline_separated() {
        let input = "\
/usr/bin/qemu-system-x86_64\n\
-no-reboot\n\
-cpu\n\
host,pmu=on\n\
-m\n\
16G\n\
-machine\n\
q35,accel=kvm\n\
-nodefaults\n";
        let tokens = tokenize(input);
        assert_eq!(tokens[0], "/usr/bin/qemu-system-x86_64");
        assert_eq!(tokens[1], "-no-reboot");
        assert_eq!(tokens[2], "-cpu");
        assert_eq!(tokens[3], "host,pmu=on");
        assert_eq!(tokens[4], "-m");
        assert_eq!(tokens[5], "16G");
        assert_eq!(tokens[6], "-machine");
        assert_eq!(tokens[7], "q35,accel=kvm");
        assert_eq!(tokens[8], "-nodefaults");
    }

    #[test]
    fn cmdline_format_null_separated() {
        let input = "/usr/bin/qemu\0-m\016G\0-nodefaults\0";
        let tokens = tokenize(input);
        assert_eq!(tokens, vec!["/usr/bin/qemu", "-m", "16G", "-nodefaults"]);
    }
}
