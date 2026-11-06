/*
 * Copyright (c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */
//! Lexer and parser for the GRUB script language (the subset grub-mkconfig
//! and distribution bootstrap configs use), following GRUB 2.06's
//! `script/yylex.l` and `script/parser.y`.

use anyhow::{bail, Result};

/// One piece of a word.
#[derive(Debug, Clone, PartialEq)]
pub enum Seg {
    /// Unquoted literal text (escapes resolved). Empty text adds no argument.
    Text(String),
    /// Text inside single or double quotes. Always creates the argument,
    /// even when empty.
    Quoted(String),
    /// `$name` / `${name}`; unquoted values are split on whitespace.
    Var { name: String, quoted: bool },
}

pub type Word = Vec<Seg>;

#[derive(Debug, Clone)]
pub enum Arg {
    Word(Word),
    /// `{ ... }`: the raw source between the braces plus its parsed body.
    Block {
        raw: String,
        body: Vec<Cmd>,
    },
}

#[derive(Debug, Clone)]
pub enum Cmd {
    Simple(Vec<Arg>),
    If {
        branches: Vec<(Vec<Cmd>, Vec<Cmd>)>,
        otherwise: Option<Vec<Cmd>>,
    },
    For {
        var: String,
        words: Vec<Word>,
        body: Vec<Cmd>,
    },
    While {
        until: bool,
        cond: Vec<Cmd>,
        body: Vec<Cmd>,
    },
    Function {
        name: String,
        body: Vec<Cmd>,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// A word; `plain` holds its text when it is a single unescaped,
    /// unquoted literal (only those can be reserved words).
    Word {
        word: Word,
        plain: Option<String>,
    },
    Newline,
    Semi,
    LBr,
    RBr,
    Op,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
}

const DELIMS: &[u8] = b"{}|&;<> \t\n";

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Parse a `$...` reference at `s[i]` (which is `$`). Returns the variable
/// name and the index after it, or `None` if this `$` is not a reference.
fn parse_var(s: &[u8], i: usize) -> Option<(String, usize)> {
    let take = |from: usize| -> Option<(String, usize)> {
        let c = *s.get(from)?;
        if b"?#*@".contains(&c) {
            return Some(((c as char).to_string(), from + 1));
        }
        let mut k = from;
        if c.is_ascii_digit() {
            while k < s.len() && s[k].is_ascii_digit() {
                k += 1;
            }
        } else if is_name_start(c) {
            while k < s.len() && is_name_char(s[k]) {
                k += 1;
            }
        } else {
            return None;
        }
        Some((String::from_utf8_lossy(&s[from..k]).into_owned(), k))
    };
    if s.get(i + 1) == Some(&b'{') {
        let (name, k) = take(i + 2)?;
        (s.get(k) == Some(&b'}')).then_some((name, k + 1))
    } else {
        take(i + 1)
    }
}

fn lex(src: &str) -> Result<Vec<Token>> {
    let s = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    let mut push = |tok, start, end| toks.push(Token { tok, start, end });
    while i < s.len() {
        let c = s[i];
        match c {
            b' ' | b'\t' => i += 1,
            b'\\' if s.get(i + 1) == Some(&b'\n') => i += 2,
            b'#' => {
                while i < s.len() && s[i] != b'\n' {
                    i += 1;
                }
            }
            b'\n' => {
                push(Tok::Newline, i, i + 1);
                i += 1;
            }
            b';' => {
                if s.get(i + 1) == Some(&b';') {
                    push(Tok::Op, i, i + 2);
                    i += 2;
                } else {
                    push(Tok::Semi, i, i + 1);
                    i += 1;
                }
            }
            b'{' => {
                push(Tok::LBr, i, i + 1);
                i += 1;
            }
            b'}' => {
                push(Tok::RBr, i, i + 1);
                i += 1;
            }
            b'|' | b'&' | b'<' | b'>' => {
                let len = if matches!(c, b'|' | b'&') && s.get(i + 1) == Some(&c) {
                    2
                } else {
                    1
                };
                push(Tok::Op, i, i + len);
                i += len;
            }
            _ => {
                let (word, plain, end) = lex_word(s, i)?;
                push(Tok::Word { word, plain }, i, end);
                i = end;
            }
        }
    }
    Ok(toks)
}

fn flush(segs: &mut Word, text: &mut Vec<u8>, quoted: bool) {
    if !text.is_empty() {
        let t = String::from_utf8_lossy(text).into_owned();
        segs.push(if quoted { Seg::Quoted(t) } else { Seg::Text(t) });
        text.clear();
    }
}

fn lex_word(s: &[u8], mut i: usize) -> Result<(Word, Option<String>, usize)> {
    let mut segs: Word = Vec::new();
    let mut text = Vec::new();
    let mut plain = true;
    while i < s.len() {
        let c = s[i];
        if DELIMS.contains(&c) {
            break;
        }
        match c {
            b'\\' => {
                plain = false;
                match s.get(i + 1) {
                    Some(b'\n') => i += 2,
                    Some(&n) => {
                        text.push(n);
                        i += 2;
                    }
                    None => {
                        text.push(b'\\');
                        i += 1;
                    }
                }
            }
            b'\'' => {
                plain = false;
                flush(&mut segs, &mut text, false);
                let Some(len) = s[i + 1..].iter().position(|&b| b == b'\'') else {
                    bail!("unterminated single quote");
                };
                segs.push(Seg::Quoted(
                    String::from_utf8_lossy(&s[i + 1..i + 1 + len]).into_owned(),
                ));
                i += len + 2;
            }
            b'"' => {
                plain = false;
                flush(&mut segs, &mut text, false);
                i = lex_dquote(s, i + 1, &mut segs)?;
            }
            b'$' => {
                plain = false;
                if s.get(i + 1) == Some(&b'"') {
                    // $"..." is a translatable string; treat it as "...".
                    flush(&mut segs, &mut text, false);
                    i = lex_dquote(s, i + 2, &mut segs)?;
                } else if let Some((name, end)) = parse_var(s, i) {
                    flush(&mut segs, &mut text, false);
                    segs.push(Seg::Var {
                        name,
                        quoted: false,
                    });
                    i = end;
                } else {
                    text.push(b'$');
                    i += 1;
                }
            }
            _ => {
                text.push(c);
                i += 1;
            }
        }
    }
    let plain = (plain && segs.is_empty()).then(|| String::from_utf8_lossy(&text).into_owned());
    flush(&mut segs, &mut text, false);
    Ok((segs, plain, i))
}

/// Lex a double-quoted string starting after the opening quote; returns the
/// index after the closing quote.
fn lex_dquote(s: &[u8], mut i: usize, segs: &mut Word) -> Result<usize> {
    let mut text = Vec::new();
    // The quotes alone make the argument exist, even if everything is empty.
    segs.push(Seg::Quoted(String::new()));
    loop {
        let Some(&c) = s.get(i) else {
            bail!("unterminated double quote");
        };
        match c {
            b'"' => {
                flush(segs, &mut text, true);
                return Ok(i + 1);
            }
            b'\\' => match s.get(i + 1) {
                Some(&n @ (b'$' | b'\\' | b'"')) => {
                    text.push(n);
                    i += 2;
                }
                Some(b'\n') => i += 2,
                _ => {
                    text.push(b'\\');
                    i += 1;
                }
            },
            b'$' => {
                if let Some((name, end)) = parse_var(s, i) {
                    flush(segs, &mut text, true);
                    segs.push(Seg::Var { name, quoted: true });
                    i = end;
                } else {
                    text.push(b'$');
                    i += 1;
                }
            }
            _ => {
                text.push(c);
                i += 1;
            }
        }
    }
}

struct Parser<'a> {
    src: &'a str,
    toks: Vec<Token>,
    pos: usize,
}

const RESERVED: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "in", "do", "done", "while", "until", "function",
];

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_reserved(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word { plain: Some(p), .. }) if RESERVED.contains(&p.as_str()) => Some(p),
            _ => None,
        }
    }

    fn skip_delims(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline | Tok::Semi)) {
            self.pos += 1;
        }
    }

    fn expect_reserved(&mut self, word: &str) -> Result<()> {
        if self.peek_reserved() != Some(word) {
            bail!("syntax error: expected `{word}` near {}", self.context());
        }
        self.pos += 1;
        Ok(())
    }

    fn context(&self) -> String {
        match self.toks.get(self.pos) {
            Some(t) => {
                let line = self.src[..t.start].matches('\n').count() + 1;
                format!("line {line}: {:?}", &self.src[t.start..t.end])
            }
            None => "end of input".into(),
        }
    }

    /// Parse commands until one of the reserved `terminators`, a `}` when
    /// `brace` is set, or end of input.
    fn commands(&mut self, terminators: &[&str], brace: bool) -> Result<Vec<Cmd>> {
        let mut cmds = Vec::new();
        loop {
            self.skip_delims();
            match self.peek() {
                None => break,
                Some(Tok::RBr) if brace => break,
                _ => {}
            }
            if self
                .peek_reserved()
                .is_some_and(|r| terminators.contains(&r))
            {
                break;
            }
            cmds.push(self.command()?);
            match self.peek() {
                None | Some(Tok::Newline | Tok::Semi) => {}
                Some(Tok::RBr) if brace => {}
                _ if self
                    .peek_reserved()
                    .is_some_and(|r| terminators.contains(&r)) => {}
                _ => bail!("syntax error near {}", self.context()),
            }
        }
        Ok(cmds)
    }

    fn name(&mut self, what: &str) -> Result<String> {
        match self.peek() {
            Some(Tok::Word { plain: Some(p), .. }) => {
                let p = p.clone();
                self.pos += 1;
                Ok(p)
            }
            _ => bail!("syntax error: expected {what} near {}", self.context()),
        }
    }

    fn command(&mut self) -> Result<Cmd> {
        match self.peek_reserved() {
            Some("if") => self.if_cmd(),
            Some("for") => self.for_cmd(),
            Some(w @ ("while" | "until")) => {
                let until = w == "until";
                self.pos += 1;
                let cond = self.commands(&["do"], false)?;
                self.expect_reserved("do")?;
                let body = self.commands(&["done"], false)?;
                self.expect_reserved("done")?;
                Ok(Cmd::While { until, cond, body })
            }
            Some("function") => {
                self.pos += 1;
                let name = self.name("function name")?;
                self.skip_delims();
                let Arg::Block { body, .. } = self.block()? else {
                    unreachable!()
                };
                Ok(Cmd::Function { name, body })
            }
            Some(r) => bail!("syntax error: unexpected `{r}` near {}", self.context()),
            None => self.simple(),
        }
    }

    fn if_cmd(&mut self) -> Result<Cmd> {
        self.expect_reserved("if")?;
        let mut branches = Vec::new();
        let mut otherwise = None;
        loop {
            let cond = self.commands(&["then"], false)?;
            self.expect_reserved("then")?;
            let body = self.commands(&["elif", "else", "fi"], false)?;
            branches.push((cond, body));
            match self.peek_reserved() {
                Some("elif") => self.pos += 1,
                Some("else") => {
                    self.pos += 1;
                    otherwise = Some(self.commands(&["fi"], false)?);
                    self.expect_reserved("fi")?;
                    break;
                }
                _ => {
                    self.expect_reserved("fi")?;
                    break;
                }
            }
        }
        Ok(Cmd::If {
            branches,
            otherwise,
        })
    }

    fn for_cmd(&mut self) -> Result<Cmd> {
        self.expect_reserved("for")?;
        let var = self.name("loop variable")?;
        self.expect_reserved("in")?;
        let mut words = Vec::new();
        while let Some(Tok::Word { word, .. }) = self.peek() {
            words.push(word.clone());
            self.pos += 1;
        }
        self.skip_delims();
        self.expect_reserved("do")?;
        let body = self.commands(&["done"], false)?;
        self.expect_reserved("done")?;
        Ok(Cmd::For { var, words, body })
    }

    fn simple(&mut self) -> Result<Cmd> {
        let mut args = Vec::new();
        loop {
            match self.peek() {
                Some(Tok::Word { word, .. }) => {
                    args.push(Arg::Word(word.clone()));
                    self.pos += 1;
                }
                Some(Tok::LBr) if !args.is_empty() => args.push(self.block()?),
                _ => break,
            }
        }
        if args.is_empty() {
            bail!("syntax error near {}", self.context());
        }
        Ok(Cmd::Simple(args))
    }

    fn block(&mut self) -> Result<Arg> {
        let open_end = match self.toks.get(self.pos) {
            Some(Token {
                tok: Tok::LBr, end, ..
            }) => *end,
            _ => bail!("syntax error: expected `{{` near {}", self.context()),
        };
        self.pos += 1;
        let body = self.commands(&[], true)?;
        let close = match self.toks.get(self.pos) {
            Some(Token {
                tok: Tok::RBr,
                start,
                ..
            }) => *start,
            _ => bail!("syntax error: unterminated block near {}", self.context()),
        };
        self.pos += 1;
        Ok(Arg::Block {
            raw: self.src[open_end..close].to_string(),
            body,
        })
    }
}

/// Parse a complete script.
pub fn parse(src: &str) -> Result<Vec<Cmd>> {
    let mut p = Parser {
        src,
        toks: lex(src)?,
        pos: 0,
    };
    let cmds = p.commands(&[], false)?;
    if p.pos < p.toks.len() {
        bail!("syntax error near {}", p.context());
    }
    Ok(cmds)
}

/// Turn a config file into script source the way GRUB's config reader does:
/// carriage returns are dropped and lines starting with `#` are skipped.
pub fn config_source(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data).replace('\r', "");
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_variables_and_blocks() {
        let cmds = parse(
            "if [ \"${next_entry}\" ] ; then\n  set default=\"${next_entry}\"\nelse\n   set default=\"0\"\nfi\n\
             menuentry 'A b' --id x {\n\techo\t'hi'\n}\n",
        )
        .unwrap();
        assert_eq!(cmds.len(), 2);
        let Cmd::If {
            branches,
            otherwise,
        } = &cmds[0]
        else {
            panic!()
        };
        let Cmd::Simple(args) = &branches[0].0[0] else {
            panic!()
        };
        let Arg::Word(w) = &args[1] else { panic!() };
        assert_eq!(
            w,
            &vec![
                Seg::Quoted(String::new()),
                Seg::Var {
                    name: "next_entry".into(),
                    quoted: true
                }
            ]
        );
        assert!(otherwise.is_some());
        let Cmd::Simple(args) = &cmds[1] else {
            panic!()
        };
        let Arg::Block { raw, body } = &args[4] else {
            panic!()
        };
        assert_eq!(raw, "\n\techo\t'hi'\n");
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn config_source_drops_comment_lines() {
        assert_eq!(
            config_source(b"# x\r\nset a=1\r\n  # y\n"),
            "set a=1\n  # y\n"
        );
    }
}
