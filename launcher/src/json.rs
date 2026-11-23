//! A strict, bounded JSON reader for the contract file and the stage-bind record (contract §4 step 1). Only what those
//! need: objects, arrays, strings (UTF-8, no NUL, standard escapes), non-negative integers, null and booleans. Depth
//! and sizes are bounded; duplicate keys and trailing data are refused.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

pub const MAX_DEPTH: usize = 8;
pub const MAX_ITEMS: usize = 256;
pub const MAX_STR: usize = 4096;

pub fn parse(src: &[u8]) -> Option<Value> {
    let text = core::str::from_utf8(src).ok()?;
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return None;
    }
    Some(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match *self.s.get(self.i)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Value::Str),
            b'n' => self.eat(b"null").then_some(Value::Null),
            b't' => self.eat(b"true").then_some(Value::Bool(true)),
            b'f' => self.eat(b"false").then_some(Value::Bool(false)),
            b'0'..=b'9' => self.int().map(Value::Int),
            _ => None,
        }
    }

    fn int(&mut self) -> Option<u64> {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        let digits = &self.s[start..self.i];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') || digits.len() > 20 {
            return None; // no leading zeros; fits u64
        }
        if self.i < self.s.len() && matches!(self.s[self.i], b'.' | b'e' | b'E' | b'-' | b'+') {
            return None; // integers only
        }
        core::str::from_utf8(digits).ok()?.parse().ok()
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'u' => {
                            let h = core::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
                            self.i += 4;
                            let n = u32::from_str_radix(h, 16).ok()?;
                            char::from_u32(n)? // surrogates are refused (no pairs needed here)
                        }
                        _ => return None,
                    };
                    out.push(ch);
                }
                0..=0x1f => return None, // control characters must be escaped
                _ => {
                    // Copy the whole UTF-8 sequence (the input was validated as UTF-8 up front).
                    let start = self.i - 1;
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    out.push_str(core::str::from_utf8(self.s.get(start..start + len)?).ok()?);
                    self.i = start + len;
                }
            }
            if out.len() > MAX_STR {
                return None;
            }
        }
        if out.contains('\0') {
            return None;
        }
        Some(out)
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b"]") {
            return Some(Value::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            if items.len() > MAX_ITEMS {
                return None;
            }
            self.ws();
            if self.eat(b"]") {
                return Some(Value::Arr(items));
            }
            if !self.eat(b",") {
                return None;
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        self.i += 1;
        let mut fields: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.eat(b"}") {
            return Some(Value::Obj(fields));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return None;
            }
            let k = self.string()?;
            if fields.iter().any(|(f, _)| *f == k) {
                return None; // duplicate key
            }
            self.ws();
            if !self.eat(b":") {
                return None;
            }
            let v = self.value(depth + 1)?;
            fields.push((k, v));
            if fields.len() > MAX_ITEMS {
                return None;
            }
            self.ws();
            if self.eat(b"}") {
                return Some(Value::Obj(fields));
            }
            if !self.eat(b",") {
                return None;
            }
        }
    }
}

impl Value {
    /// The object's fields, if it has EXACTLY these keys (in any order); else None.
    pub fn exact<'a>(&'a self, keys: &[&str]) -> Option<Vec<&'a Value>> {
        let Value::Obj(f) = self else { return None };
        if f.len() != keys.len() {
            return None;
        }
        keys.iter().map(|k| f.iter().find(|(n, _)| n == k).map(|(_, v)| v)).collect()
    }
    pub fn str(&self) -> Option<&str> {
        if let Value::Str(s) = self { Some(s) } else { None }
    }
    pub fn int(&self) -> Option<u64> {
        if let Value::Int(n) = self { Some(*n) } else { None }
    }
    pub fn arr(&self) -> Option<&[Value]> {
        if let Value::Arr(a) = self { Some(a) } else { None }
    }
}

/// A JSON string literal for `s` (for writing the record).
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_subset() {
        let v = parse(br#" {"a": [1, 2, {"b": null}], "s": "x\u0041\n", "t": true} "#).unwrap();
        let f = v.exact(&["a", "s", "t"]).unwrap();
        assert_eq!(f[1].str(), Some("xA\n"));
        assert_eq!(f[0].arr().unwrap().len(), 3);
        assert_eq!(parse(b"18446744073709551615").unwrap().int(), Some(u64::MAX));
        assert_eq!(parse("\"\u{e9}\"".as_bytes()).unwrap().str(), Some("\u{e9}"));
    }

    #[test]
    fn refuses_everything_else() {
        for bad in [
            &b"{\"a\":1,\"a\":2}"[..], b"[1,]", b"{,}", b"01", b"-1", b"1.5", b"1e3", b"\"\x01\"", b"\"\\u0000\"",
            b"\"\\ud800\"", b"\"\\q\"", b"nul", b"{} x", b"[[[[[[[[[[1]]]]]]]]]]", b"\xff", b"18446744073709551616",
        ] {
            assert!(parse(bad).is_none(), "{:?}", core::str::from_utf8(bad));
        }
        let big = format!("[{}0]", "0,".repeat(MAX_ITEMS));
        assert!(parse(big.as_bytes()).is_none());
        assert!(parse(format!("\"{}\"", "a".repeat(MAX_STR + 1)).as_bytes()).is_none());
    }

    #[test]
    fn quote_round_trips() {
        for s in ["/data/x", "a\"b\\c", "\u{e9}\u{1f600}", "tab\there"] {
            assert_eq!(parse(quote(s).as_bytes()).unwrap().str(), Some(s));
        }
    }
}
