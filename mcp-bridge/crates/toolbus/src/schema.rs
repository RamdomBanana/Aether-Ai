//! A strict validator for the JSON Schema subset that `proto/schemas` is written in.
//!
//! The schemas are the single source of truth for every wire contract, so toolbus
//! validates against them at runtime rather than re-encoding their rules in Rust.
//! Because the subset is closed (see `x-aether` notes in `common.schema.json`), a small
//! purpose-built validator is safer than a general engine: [`SchemaSet::load`] refuses any
//! keyword outside the subset, so a schema edit that this code does not understand fails at
//! startup instead of silently validating nothing.
//!
//! Supported keywords: `$ref` (local and cross-file), `type`, `enum`, `const`, `properties`,
//! `required`, `additionalProperties` (boolean), `items`, `minItems`, `maxItems`,
//! `uniqueItems`, `minimum`, `maximum`, `exclusiveMinimum`, `minLength`, `maxLength`,
//! `pattern`, `format: date-time`, `contentEncoding: base64`, `oneOf`, `anyOf`.
//!
//! Deliberate strictness beyond the JSON Schema text:
//!
//! * `type: integer` accepts only integer *representations*: `3` yes, `3.0` and `3e0` no.
//! * `contentEncoding: base64` is an assertion here (standard alphabet, `=` padding).
//! * `format: date-time` is checked as RFC 3339 including calendar ranges; other formats
//!   (such as `uri`) are annotations only, and the schema backs them with `pattern`.
//! * Patterns use the `regex` crate, where `$` matches only at the end of the text, as in
//!   ECMAScript without the `m` flag, so `"tr_1\n"` does not match `^tr_[0-9A-Za-z]+$`.
//!
//! Violations never echo instance values, only a JSON pointer and the failed keyword, so
//! attacker-controlled text cannot reach error messages or logs through this module.

use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde_json::{Map, Number, Value};

/// Every schema `$id` must be this prefix plus the file name. The host is non-resolvable.
pub const ID_PREFIX: &str = "https://schemas.aether.invalid/v1/";

const MAX_VIOLATIONS: usize = 8;
const MAX_DEPTH: usize = 64;

const KEYWORDS: &[&str] = &[
    "$schema", "$id", "$ref", "$defs", "title", "description", "default", "type", "enum", "const", "properties", "required",
    "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "exclusiveMinimum",
    "minLength", "maxLength", "pattern", "format", "contentEncoding", "oneOf", "anyOf",
];

/// A problem found while loading schemas (never while validating an instance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

fn fail<T>(message: String) -> Result<T, SchemaError> {
    Err(SchemaError(message))
}

/// Points at one schema: a file plus an RFC 6901 pointer into it (empty for the root).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemaRef {
    /// File name, for example `toolbus.schema.json`.
    pub file: String,
    /// Pointer such as `/$defs/WebCrawlAndIndexParams`.
    pub pointer: String,
}

impl SchemaRef {
    /// Builds a reference from parts.
    pub fn new(file: &str, pointer: &str) -> Self {
        SchemaRef { file: file.to_owned(), pointer: pointer.to_owned() }
    }

    /// Parses `#/$defs/X` (relative to `current_file`) or `other.schema.json#/$defs/X`.
    pub fn parse(current_file: &str, reference: &str) -> Self {
        match reference.split_once('#') {
            Some((file, pointer)) => {
                let file = if file.is_empty() { current_file } else { file };
                SchemaRef::new(file, pointer)
            }
            None => SchemaRef::new(reference, ""),
        }
    }
}

impl fmt::Display for SchemaRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.file, self.pointer)
    }
}

/// One failed constraint: where (relative to the validated instance) and which keyword.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// RFC 6901 pointer to the offending value; empty for the instance itself.
    pub pointer: String,
    /// The keyword that failed, for example `maxLength`.
    pub keyword: &'static str,
}

struct Collected {
    patterns: HashMap<String, Regex>,
    refs: Vec<(String, String)>,
}

/// A loaded, linted, fully-resolved set of schema documents.
#[derive(Debug)]
pub struct SchemaSet {
    docs: HashMap<String, Value>,
    patterns: HashMap<String, Regex>,
}

impl SchemaSet {
    /// Parses and lints `(file name, JSON text)` pairs. Fails if any document is not JSON,
    /// has the wrong `$id`, uses a keyword outside the subset, contains an invalid regex,
    /// or has a `$ref` that does not resolve.
    pub fn load(sources: &[(&str, &str)]) -> Result<SchemaSet, SchemaError> {
        let mut docs: HashMap<String, Value> = HashMap::new();
        for (name, text) in sources {
            let doc: Value = serde_json::from_str(text).map_err(|e| SchemaError(format!("{name}: invalid JSON: {e}")))?;
            let expected = format!("{ID_PREFIX}{name}");
            if doc.get("$id").and_then(Value::as_str) != Some(expected.as_str()) {
                return fail(format!("{name}: $id must be {expected}"));
            }
            if docs.insert((*name).to_owned(), doc).is_some() {
                return fail(format!("{name}: provided twice"));
            }
        }
        let mut collected = Collected { patterns: HashMap::new(), refs: Vec::new() };
        for (name, doc) in &docs {
            walk(name, doc, "#", &mut collected)?;
        }
        let set = SchemaSet { docs, patterns: collected.patterns };
        for (file, reference) in &collected.refs {
            if !set.contains(&SchemaRef::parse(file, reference)) {
                return fail(format!("{file}: unresolved $ref {reference}"));
            }
        }
        Ok(set)
    }

    /// File names, sorted.
    pub fn files(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.docs.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// The root document of a file.
    pub fn doc(&self, file: &str) -> Option<&Value> {
        self.docs.get(file)
    }

    /// Whether `target` resolves.
    pub fn contains(&self, target: &SchemaRef) -> bool {
        self.lookup(target).is_some()
    }

    /// The schema node `target` points at, if it exists.
    pub fn get(&self, target: &SchemaRef) -> Option<&Value> {
        self.lookup(target)
    }

    fn lookup(&self, target: &SchemaRef) -> Option<&Value> {
        let mut node = self.docs.get(&target.file)?;
        if target.pointer.is_empty() {
            return Some(node);
        }
        for token in target.pointer.strip_prefix('/')?.split('/') {
            let token = token.replace("~1", "/").replace("~0", "~");
            node = node.as_object()?.get(&token)?;
        }
        Some(node)
    }

    /// Validates `instance` against `target`. An empty result means valid. At most eight
    /// violations are reported.
    pub fn validate(&self, target: &SchemaRef, instance: &Value) -> Vec<Violation> {
        let mut out = Vec::new();
        match self.lookup(target) {
            Some(schema) => self.check(&target.file, schema, instance, &mut String::new(), &mut out, 0),
            None => push(&mut out, "", "$ref"),
        }
        out
    }

    fn is_valid(&self, file: &str, schema: &Value, instance: &Value, depth: usize) -> bool {
        let mut out = Vec::new();
        self.check(file, schema, instance, &mut String::new(), &mut out, depth + 1);
        out.is_empty()
    }

    fn check(&self, file: &str, schema: &Value, inst: &Value, path: &mut String, out: &mut Vec<Violation>, depth: usize) {
        if out.len() >= MAX_VIOLATIONS {
            return;
        }
        if depth > MAX_DEPTH {
            push(out, path, "depth");
            return;
        }
        let Some(map) = schema.as_object() else { return };

        if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
            let target = SchemaRef::parse(file, reference);
            match self.lookup(&target) {
                Some(resolved) => self.check(&target.file, resolved, inst, path, out, depth + 1),
                None => push(out, path, "$ref"),
            }
        }
        if let Some(expected) = map.get("type") {
            if !type_matches(expected, inst) {
                push(out, path, "type");
                return;
            }
        }
        if let Some(expected) = map.get("const") {
            if expected != inst {
                push(out, path, "const");
            }
        }
        if let Some(Value::Array(options)) = map.get("enum") {
            if !options.contains(inst) {
                push(out, path, "enum");
            }
        }
        match inst {
            Value::Number(n) => check_number(map, n, path, out),
            Value::String(s) => self.check_string(map, s, path, out),
            Value::Array(items) => self.check_array(file, map, items, path, out, depth),
            Value::Object(obj) => self.check_object(file, map, obj, path, out, depth),
            _ => {}
        }
        if let Some(Value::Array(branches)) = map.get("oneOf") {
            let matched = branches.iter().filter(|b| self.is_valid(file, b, inst, depth)).count();
            if matched != 1 {
                push(out, path, "oneOf");
            }
        }
        if let Some(Value::Array(branches)) = map.get("anyOf") {
            if !branches.iter().any(|b| self.is_valid(file, b, inst, depth)) {
                push(out, path, "anyOf");
            }
        }
    }

    fn check_string(&self, schema: &Map<String, Value>, s: &str, path: &str, out: &mut Vec<Violation>) {
        if schema.contains_key("minLength") || schema.contains_key("maxLength") {
            let chars = s.chars().count() as u64;
            if schema.get("maxLength").and_then(Value::as_u64).is_some_and(|max| chars > max) {
                push(out, path, "maxLength");
            }
            if schema.get("minLength").and_then(Value::as_u64).is_some_and(|min| chars < min) {
                push(out, path, "minLength");
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            match self.patterns.get(pattern) {
                Some(re) if re.is_match(s) => {}
                _ => push(out, path, "pattern"),
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time") && !is_rfc3339(s) {
            push(out, path, "format");
        }
        if schema.get("contentEncoding").and_then(Value::as_str) == Some("base64") && !is_base64(s) {
            push(out, path, "contentEncoding");
        }
    }

    fn check_array(&self, file: &str, schema: &Map<String, Value>, items: &[Value], path: &mut String, out: &mut Vec<Violation>, depth: usize) {
        // Size limits first: nothing below does work proportional to an unbounded array.
        if schema.get("maxItems").and_then(Value::as_u64).is_some_and(|max| items.len() as u64 > max) {
            push(out, path, "maxItems");
            return;
        }
        if schema.get("minItems").and_then(Value::as_u64).is_some_and(|min| (items.len() as u64) < min) {
            push(out, path, "minItems");
        }
        if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
            'outer: for (i, a) in items.iter().enumerate() {
                for b in &items[i + 1..] {
                    if a == b {
                        push(out, path, "uniqueItems");
                        break 'outer;
                    }
                }
            }
        }
        if let Some(element_schema) = schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                let mark = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                self.check(file, element_schema, item, path, out, depth + 1);
                path.truncate(mark);
            }
        }
    }

    fn check_object(&self, file: &str, schema: &Map<String, Value>, obj: &Map<String, Value>, path: &mut String, out: &mut Vec<Violation>, depth: usize) {
        if let Some(Value::Array(required)) = schema.get("required") {
            for name in required.iter().filter_map(Value::as_str) {
                if !obj.contains_key(name) {
                    let mark = path.len();
                    push_token(path, name);
                    push(out, path, "required");
                    path.truncate(mark);
                }
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        if let Some(props) = props {
            for (name, sub) in props {
                if let Some(value) = obj.get(name) {
                    let mark = path.len();
                    push_token(path, name);
                    self.check(file, sub, value, path, out, depth + 1);
                    path.truncate(mark);
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for name in obj.keys() {
                if !props.is_some_and(|p| p.contains_key(name)) {
                    let mark = path.len();
                    push_token(path, name);
                    push(out, path, "additionalProperties");
                    path.truncate(mark);
                }
            }
        }
    }
}

fn walk(file: &str, node: &Value, location: &str, out: &mut Collected) -> Result<(), SchemaError> {
    let Some(map) = node.as_object() else {
        return fail(format!("{file} {location}: a schema must be an object"));
    };
    for (key, value) in map {
        if key.starts_with("x-") {
            continue;
        }
        if !KEYWORDS.contains(&key.as_str()) {
            return fail(format!("{file} {location}: keyword '{key}' is outside the supported subset"));
        }
        match key.as_str() {
            "$ref" => match value.as_str() {
                Some(reference) => out.refs.push((file.to_owned(), reference.to_owned())),
                None => return fail(format!("{file} {location}: $ref must be a string")),
            },
            "pattern" => {
                let Some(pattern) = value.as_str() else {
                    return fail(format!("{file} {location}: pattern must be a string"));
                };
                if !out.patterns.contains_key(pattern) {
                    match Regex::new(pattern) {
                        Ok(re) => {
                            out.patterns.insert(pattern.to_owned(), re);
                        }
                        Err(e) => return fail(format!("{file} {location}: invalid pattern: {e}")),
                    }
                }
            }
            "$defs" | "properties" => {
                let Some(children) = value.as_object() else {
                    return fail(format!("{file} {location}: {key} must be an object"));
                };
                for (name, sub) in children {
                    walk(file, sub, &format!("{location}/{key}/{name}"), out)?;
                }
            }
            "items" => walk(file, value, &format!("{location}/items"), out)?,
            "oneOf" | "anyOf" => {
                let Some(branches) = value.as_array() else {
                    return fail(format!("{file} {location}: {key} must be an array"));
                };
                for (i, sub) in branches.iter().enumerate() {
                    walk(file, sub, &format!("{location}/{key}/{i}"), out)?;
                }
            }
            "additionalProperties" => {
                if !value.is_boolean() {
                    return fail(format!("{file} {location}: additionalProperties must be a boolean"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn push(out: &mut Vec<Violation>, path: &str, keyword: &'static str) {
    if out.len() < MAX_VIOLATIONS {
        out.push(Violation { pointer: path.to_owned(), keyword });
    }
}

fn push_token(path: &mut String, token: &str) {
    path.push('/');
    for c in token.chars() {
        match c {
            '~' => path.push_str("~0"),
            '/' => path.push_str("~1"),
            other => path.push(other),
        }
    }
}

fn type_matches(expected: &Value, inst: &Value) -> bool {
    match expected {
        Value::String(name) => matches_type(name, inst),
        Value::Array(names) => names.iter().filter_map(Value::as_str).any(|name| matches_type(name, inst)),
        _ => false,
    }
}

fn matches_type(name: &str, inst: &Value) -> bool {
    match name {
        "object" => inst.is_object(),
        "array" => inst.is_array(),
        "string" => inst.is_string(),
        "boolean" => inst.is_boolean(),
        "null" => inst.is_null(),
        "number" => inst.is_number(),
        "integer" => matches!(inst, Value::Number(n) if n.is_i64() || n.is_u64()),
        _ => false,
    }
}

fn check_number(schema: &Map<String, Value>, n: &Number, path: &str, out: &mut Vec<Violation>) {
    let Some(v) = n.as_f64() else { return };
    if schema.get("minimum").and_then(Value::as_f64).is_some_and(|min| v < min) {
        push(out, path, "minimum");
    }
    if schema.get("maximum").and_then(Value::as_f64).is_some_and(|max| v > max) {
        push(out, path, "maximum");
    }
    if schema.get("exclusiveMinimum").and_then(Value::as_f64).is_some_and(|min| v <= min) {
        push(out, path, "exclusiveMinimum");
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// RFC 3339 `date-time`: `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)` with calendar ranges.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if !s.is_ascii() || b.len() < 20 {
        return false;
    }
    let num = |from: usize, to: usize| -> Option<u32> {
        let mut v = 0u32;
        for &c in b.get(from..to)? {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u32::from(c - b'0');
        }
        Some(v)
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19))
    else {
        return false;
    };
    if b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't') || b[13] != b':' || b[16] != b':' {
        return false;
    }
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            if i + 6 != b.len() || b[i + 3] != b':' {
                return false;
            }
            matches!((num(i + 1, i + 3), num(i + 4, i + 6)), (Some(h), Some(m)) if h <= 23 && m <= 59)
        }
        _ => false,
    }
}

/// Standard-alphabet base64 with `=` padding. Trailing-bit canonicality is not checked.
pub(crate) fn is_base64(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return false;
    }
    let padding = b.iter().rev().take_while(|&&c| c == b'=').count();
    if padding > 2 {
        return false;
    }
    b[..b.len() - padding].iter().all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MINI: &str = r##"{
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "https://schemas.aether.invalid/v1/mini.schema.json",
      "$defs": {
        "Id": { "type": "string", "pattern": "^t_[0-9A-Za-z]{1,8}$" },
        "Name": { "type": "string", "minLength": 2, "maxLength": 4 },
        "Count": { "type": "integer", "minimum": 1, "maximum": 10 },
        "Ratio": { "type": "number", "exclusiveMinimum": 0, "maximum": 1 },
        "Mode": { "enum": ["a", "b"] },
        "Tag": { "const": "x" },
        "When": { "type": "string", "format": "date-time" },
        "Blob": { "type": "string", "contentEncoding": "base64" },
        "Tags": { "type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": true, "items": { "$ref": "#/$defs/Name" } },
        "Either": { "oneOf": [ { "type": "string" }, { "type": "integer" } ] },
        "Maybe": { "anyOf": [ { "type": "null" }, { "$ref": "#/$defs/Count" } ] },
        "Both": { "oneOf": [ { "type": "integer" }, { "type": "number" } ] },
        "Obj": {
          "type": "object",
          "properties": { "id": { "$ref": "#/$defs/Id" }, "n": { "$ref": "#/$defs/Count" }, "a/b": { "type": "string" } },
          "required": ["id"],
          "additionalProperties": false
        },
        "Open": { "type": "object", "properties": { "k": { "type": "string" } }, "additionalProperties": true },
        "Nullable": { "type": ["integer", "null"] }
      }
    }"##;

    fn mini() -> SchemaSet {
        SchemaSet::load(&[("mini.schema.json", MINI)]).unwrap()
    }

    fn check(def: &str, v: Value) -> Vec<Violation> {
        mini().validate(&SchemaRef::new("mini.schema.json", &format!("/$defs/{def}")), &v)
    }

    fn ok(def: &str, v: Value) {
        assert!(check(def, v.clone()).is_empty(), "{def} should accept {v}");
    }

    fn bad(def: &str, v: Value, keyword: &str) {
        let got = check(def, v.clone());
        assert!(got.iter().any(|x| x.keyword == keyword), "{def} should reject {v} with {keyword}, got {got:?}");
    }

    #[test]
    fn integer_is_strict_about_representation() {
        ok("Count", json!(3));
        bad("Count", json!(3.0), "type");
        bad("Count", json!(2.5), "type");
        bad("Count", json!("3"), "type");
        bad("Count", json!(true), "type");
        bad("Count", json!(null), "type");
        bad("Count", json!(0), "minimum");
        bad("Count", json!(11), "maximum");
    }

    #[test]
    fn number_bounds() {
        ok("Ratio", json!(0.5));
        ok("Ratio", json!(1));
        bad("Ratio", json!(0), "exclusiveMinimum");
        bad("Ratio", json!(1.01), "maximum");
    }

    #[test]
    fn enum_const_and_type_arrays() {
        ok("Mode", json!("a"));
        bad("Mode", json!("c"), "enum");
        ok("Tag", json!("x"));
        bad("Tag", json!("y"), "const");
        ok("Nullable", json!(null));
        ok("Nullable", json!(4));
        bad("Nullable", json!("4"), "type");
    }

    #[test]
    fn string_lengths_count_characters_not_bytes() {
        ok("Name", json!("ab"));
        ok("Name", json!("éééé"));
        bad("Name", json!("a"), "minLength");
        bad("Name", json!("abcde"), "maxLength");
        bad("Name", json!("ééééé"), "maxLength");
    }

    #[test]
    fn pattern_is_anchored_by_the_schema_and_dollar_means_end_of_text() {
        ok("Id", json!("t_abc"));
        bad("Id", json!("t_abc\n"), "pattern");
        bad("Id", json!("xt_abc"), "pattern");
        bad("Id", json!("t_"), "pattern");
        bad("Id", json!("t_123456789"), "pattern");
        bad("Id", json!(5), "type");
    }

    #[test]
    fn date_time_checks_calendar_ranges() {
        for good in ["2026-11-18T03:04:05Z", "2026-11-18T03:04:05.123Z", "2026-11-18t03:04:05z", "2026-11-18T03:04:05+10:30", "2024-02-29T00:00:00Z", "2026-12-31T23:59:60Z"] {
            ok("When", json!(good));
        }
        for wrong in ["yesterday", "2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z", "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-11-18T24:00:00Z",
                      "2026-11-18T03:60:00Z", "2026-11-18 03:04:05Z", "2026-11-18T03:04:05", "2026-11-18T03:04:05+1030", "2026-11-18T03:04:05.Z", "2026-11-18T03:04:05+24:00", "2026-11-18T03:04:05Zjunk", "２０２６-11-18T03:04:05Z"] {
            bad("When", json!(wrong), "format");
        }
    }

    #[test]
    fn base64_is_asserted() {
        for good in ["", "YQ==", "YWI=", "YWJj", "YSxiCjEsMg=="] {
            ok("Blob", json!(good));
        }
        for wrong in ["Y", "YQ=", "YQ===", "YQ=a", "Y Q==", "YQ==\n", "YW*j", "=YQ="] {
            bad("Blob", json!(wrong), "contentEncoding");
        }
    }

    #[test]
    fn arrays() {
        ok("Tags", json!(["ab", "cd"]));
        bad("Tags", json!([]), "minItems");
        bad("Tags", json!(["ab", "cd", "ef", "gh"]), "maxItems");
        bad("Tags", json!(["ab", "ab"]), "uniqueItems");
        bad("Tags", json!(["ab", "x"]), "minLength");
        let v = check("Tags", json!(["ab", "x"]));
        assert_eq!(v[0].pointer, "/1");
    }

    #[test]
    fn oversized_arrays_are_rejected_before_any_per_item_work() {
        let big: Vec<Value> = (0..200_000).map(|i| json!(format!("n{i}"))).collect();
        let v = check("Tags", Value::Array(big));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].keyword, "maxItems");
    }

    #[test]
    fn one_of_and_any_of() {
        ok("Either", json!("s"));
        ok("Either", json!(1));
        bad("Either", json!(1.5), "oneOf");
        ok("Both", json!(1.5));
        bad("Both", json!(1), "oneOf"); // matches both branches
        ok("Maybe", json!(null));
        ok("Maybe", json!(5));
        bad("Maybe", json!(50), "anyOf");
    }

    #[test]
    fn objects_required_unknown_and_nested_pointers() {
        ok("Obj", json!({"id": "t_1"}));
        ok("Obj", json!({"id": "t_1", "n": 2}));
        bad("Obj", json!({}), "required");
        bad("Obj", json!({"id": "t_1", "extra": 1}), "additionalProperties");
        bad("Obj", json!([]), "type");
        let v = check("Obj", json!({"id": "t_1", "n": 99}));
        assert_eq!(v, vec![Violation { pointer: "/n".into(), keyword: "maximum" }]);
        let v = check("Obj", json!({"id": "t_1", "zz/yy~": 1}));
        assert_eq!(v[0].pointer, "/zz~1yy~0", "pointers are RFC 6901 escaped");
        let v = check("Obj", json!({}));
        assert_eq!(v[0].pointer, "/id", "a missing member is reported at its own pointer");
        ok("Open", json!({"k": "v", "anything": [1, 2]}));
    }

    #[test]
    fn violations_are_capped_and_never_echo_values() {
        let mut obj = Map::new();
        obj.insert("id".to_owned(), json!("t_1"));
        for i in 0..40 {
            obj.insert(format!("extra{i}"), json!(i));
        }
        let v = check("Obj", Value::Object(obj));
        assert_eq!(v.len(), MAX_VIOLATIONS, "40 unknown members must be reported as at most {MAX_VIOLATIONS}");
        let secret = check("Id", json!("t_SECRET-TOKEN-VALUE"));
        assert!(!secret.is_empty());
        assert!(!format!("{secret:?}").contains("SECRET"), "violations must not echo instance values");
    }

    #[test]
    fn cross_file_refs_resolve() {
        let a = r##"{"$id":"https://schemas.aether.invalid/v1/a.schema.json","$defs":{"X":{"$ref":"b.schema.json#/$defs/Y"}}}"##;
        let b = r##"{"$id":"https://schemas.aether.invalid/v1/b.schema.json","$defs":{"Y":{"type":"string","maxLength":2}}}"##;
        let set = SchemaSet::load(&[("a.schema.json", a), ("b.schema.json", b)]).unwrap();
        let target = SchemaRef::new("a.schema.json", "/$defs/X");
        assert!(set.validate(&target, &json!("ab")).is_empty());
        assert!(!set.validate(&target, &json!("abc")).is_empty());
        assert_eq!(set.files(), vec!["a.schema.json", "b.schema.json"]);
    }

    #[test]
    fn loading_refuses_what_it_cannot_validate() {
        let load = |body: &str| {
            let text = format!("{{\"$id\":\"https://schemas.aether.invalid/v1/t.schema.json\",{body}}}");
            SchemaSet::load(&[("t.schema.json", text.as_str())])
        };
        assert!(load(r#""$defs":{"A":{"type":"string"}}"#).is_ok());
        assert!(load(r#""$defs":{"A":{"if":{},"then":{}}}"#).is_err(), "unsupported keyword");
        assert!(load(r#""$defs":{"A":{"not":{}}}"#).is_err());
        assert!(load(r#""$defs":{"A":{"allOf":[]}}"#).is_err());
        assert!(load(r#""$defs":{"A":{"$ref":"#/$defs/Missing"}}"#).is_err(), "dangling ref");
        assert!(load(r#""$defs":{"A":{"pattern":"("}}"#).is_err(), "bad regex");
        assert!(load(r#""$defs":{"A":{"additionalProperties":{"type":"string"}}}"#).is_err(), "schema-valued additionalProperties");
        assert!(load(r#""$defs":{"A":{"x-note":"ignored","type":"string"}}"#).is_ok(), "x- annotations are ignored");
        assert!(SchemaSet::load(&[("t.schema.json", r#"{"$id":"https://elsewhere.example/t.schema.json"}"#)]).is_err(), "wrong $id");
        assert!(SchemaSet::load(&[("t.schema.json", "not json")]).is_err());
    }

    #[test]
    fn unknown_target_is_a_violation_not_a_panic() {
        let v = mini().validate(&SchemaRef::new("mini.schema.json", "/$defs/Nope"), &json!(1));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].keyword, "$ref");
    }
}
