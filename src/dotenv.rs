use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Blank,
    Comment(String),
    Var { key: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Parses dotenv text into items, keeping comments and blank lines so the
/// file can be written back in the same shape.
pub fn parse(input: &str) -> Result<Vec<Item>, ParseError> {
    let mut items = Vec::new();
    let mut p = Parser {
        src: input,
        pos: 0,
        line: 1,
    };

    while !p.eof() {
        let start_line = p.line;
        let raw = p.peek_line();
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            items.push(Item::Blank);
            p.skip_line();
            continue;
        }
        if let Some(text) = trimmed.strip_prefix('#') {
            items.push(Item::Comment(text.to_string()));
            p.skip_line();
            continue;
        }

        p.skip_inline_ws();
        if p.rest().starts_with("export ") || p.rest().starts_with("export\t") {
            p.pos += "export".len();
            p.skip_inline_ws();
        }

        let key_len = p
            .rest()
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'))
            .unwrap_or(p.rest().len());
        let key = p.rest()[..key_len].to_string();
        if !is_valid_key(&key) {
            return Err(p.error(
                start_line,
                format!("invalid variable name in `{}`", trimmed),
            ));
        }
        p.pos += key_len;
        p.skip_inline_ws();
        if !p.rest().starts_with('=') {
            return Err(p.error(start_line, format!("expected `=` after `{key}`")));
        }
        p.pos += 1;
        p.skip_inline_ws();

        let value = match p.rest().chars().next() {
            Some('"') => {
                p.pos += 1;
                let v = p.read_double_quoted(start_line)?;
                p.expect_line_end(start_line)?;
                v
            }
            Some(q @ ('\'' | '`')) => {
                p.pos += 1;
                let v = p.read_literal(q, start_line)?;
                p.expect_line_end(start_line)?;
                v
            }
            _ => {
                let line = p.peek_line();
                p.skip_line();
                strip_inline_comment(line).trim_end().to_string()
            }
        };

        items.push(Item::Var { key, value });
    }

    Ok(items)
}

/// Variables only, with later duplicates replacing earlier ones.
pub fn parse_vars(input: &str) -> Result<Vec<(String, String)>, ParseError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in parse(input)? {
        if let Item::Var { key, value } = item {
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => out.push((key, value)),
            }
        }
    }
    Ok(out)
}

fn strip_inline_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return &line[..i];
        }
    }
    line
}

/// Quotes a value so that `parse` returns it unchanged.
pub fn quote(value: &str) -> String {
    let safe = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-./:@%+,=~^".contains(c));
    if safe {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn render(items: &[Item]) -> String {
    let mut out = String::new();
    for item in items {
        match item {
            Item::Blank => {}
            Item::Comment(text) => {
                out.push('#');
                out.push_str(text);
            }
            Item::Var { key, value } => {
                out.push_str(key);
                out.push('=');
                out.push_str(&quote(value));
            }
        }
        out.push('\n');
    }
    out
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn peek_line(&self) -> &'a str {
        let rest = self.rest();
        let end = rest.find('\n').unwrap_or(rest.len());
        rest[..end].strip_suffix('\r').unwrap_or(&rest[..end])
    }

    fn skip_line(&mut self) {
        match self.rest().find('\n') {
            Some(i) => {
                self.pos += i + 1;
                self.line += 1;
            }
            None => self.pos = self.src.len(),
        }
    }

    fn skip_inline_ws(&mut self) {
        let n = self.rest().len() - self.rest().trim_start_matches([' ', '\t']).len();
        self.pos += n;
    }

    fn error(&self, line: usize, message: String) -> ParseError {
        ParseError { line, message }
    }

    fn expect_line_end(&mut self, start_line: usize) -> Result<(), ParseError> {
        self.skip_inline_ws();
        let line = self.peek_line();
        if line.is_empty() || line.starts_with('#') {
            self.skip_line();
            Ok(())
        } else {
            Err(self.error(
                start_line,
                format!("unexpected text after closing quote: `{line}`"),
            ))
        }
    }

    fn read_double_quoted(&mut self, start_line: usize) -> Result<String, ParseError> {
        let mut out = String::new();
        let mut chars = self.rest().char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += i + 1;
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => out.push('\n'),
                    Some((_, 'r')) => out.push('\r'),
                    Some((_, 't')) => out.push('\t'),
                    Some((_, '"')) => out.push('"'),
                    Some((_, '\\')) => out.push('\\'),
                    Some((_, '$')) => out.push('$'),
                    Some((_, other)) => {
                        if other == '\n' {
                            self.line += 1;
                        }
                        out.push('\\');
                        out.push(other);
                    }
                    None => break,
                },
                '\n' => {
                    self.line += 1;
                    out.push('\n');
                }
                c => out.push(c),
            }
        }
        Err(self.error(start_line, "unterminated double-quoted value".into()))
    }

    fn read_literal(&mut self, quote: char, start_line: usize) -> Result<String, ParseError> {
        match self.rest().find(quote) {
            Some(end) => {
                let value = &self.rest()[..end];
                self.line += value.matches('\n').count();
                self.pos += end + 1;
                Ok(value.to_string())
            }
            None => Err(self.error(start_line, format!("unterminated {quote}-quoted value"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(s: &str) -> Vec<(String, String)> {
        parse_vars(s).unwrap()
    }

    fn kv(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn basic_forms() {
        let input = r#"
# database
DATABASE_URL=postgres://u:p@localhost/db
export PORT = 3000
EMPTY=
SPACED=  hello world   # trailing comment
HASH=abc#def
SINGLE='raw \n $HOME'
DOUBLE="line1\nline2 \"q\""
BACKTICK=`it's`
"#;
        assert_eq!(
            vars(input),
            vec![
                kv("DATABASE_URL", "postgres://u:p@localhost/db"),
                kv("PORT", "3000"),
                kv("EMPTY", ""),
                kv("SPACED", "hello world"),
                kv("HASH", "abc#def"),
                kv("SINGLE", "raw \\n $HOME"),
                kv("DOUBLE", "line1\nline2 \"q\""),
                kv("BACKTICK", "it's"),
            ]
        );
    }

    #[test]
    fn multiline_values() {
        let input = "KEY=\"-----BEGIN-----\nabc\n-----END-----\"\nNEXT=1\n";
        assert_eq!(
            vars(input),
            vec![
                kv("KEY", "-----BEGIN-----\nabc\n-----END-----"),
                kv("NEXT", "1")
            ]
        );
        let input = "KEY='a\nb'\nNEXT=2";
        assert_eq!(vars(input), vec![kv("KEY", "a\nb"), kv("NEXT", "2")]);
    }

    #[test]
    fn crlf_and_duplicates() {
        assert_eq!(
            vars("A=1\r\nB=2\r\nA=3\r\n"),
            vec![kv("A", "3"), kv("B", "2")]
        );
    }

    #[test]
    fn keeps_comments_and_blanks() {
        let items = parse("# top\n\nA=1 # note\n").unwrap();
        assert_eq!(
            items,
            vec![
                Item::Comment(" top".into()),
                Item::Blank,
                Item::Var {
                    key: "A".into(),
                    value: "1".into()
                },
            ]
        );
    }

    #[test]
    fn errors_have_line_numbers() {
        let err = parse("A=1\nnot a var\n").unwrap_err();
        assert_eq!(err.line, 2);
        let err = parse("A=1\nB=\"open\nC=3\n").unwrap_err();
        assert_eq!(err.line, 2);
        let err = parse("A=\"x\" junk\n").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(parse("1A=x").is_err());
    }

    #[test]
    fn line_count_after_multiline() {
        let err = parse("A=\"x\ny\"\nB=1\nbad\n").unwrap_err();
        assert_eq!(err.line, 4);
    }
}
