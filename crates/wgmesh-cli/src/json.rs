use std::fmt;

/// The little bit of JSON this binary prints, written by hand so the command line needs no
/// serialization crate to say four fixed shapes.
#[derive(Clone, PartialEq, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Number(i64),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Same as [`render`](Json::render), pretty-printed for a human reading a terminal.
    pub fn render_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Json::Number(value) => out.push_str(&value.to_string()),
            Json::Text(value) => write_text(out, value),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_text(out, key);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        let pad = "  ".repeat(depth);
        let inner = "  ".repeat(depth + 1);
        match self {
            Json::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str(&inner);
                    item.write_pretty(out, depth + 1);
                }
                out.push('\n');
                out.push_str(&pad);
                out.push(']');
            }
            Json::Object(fields) if !fields.is_empty() => {
                out.push_str("{\n");
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str(&inner);
                    write_text(out, key);
                    out.push_str(": ");
                    value.write_pretty(out, depth + 1);
                }
                out.push('\n');
                out.push_str(&pad);
                out.push('}');
            }
            other => other.write(out),
        }
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Json::Text(value.to_owned())
    }
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Json::Text(value)
    }
}

impl From<u32> for Json {
    fn from(value: u32) -> Self {
        Json::Number(i64::from(value))
    }
}

impl From<i64> for Json {
    fn from(value: i64) -> Self {
        Json::Number(value)
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Json::Bool(value)
    }
}

impl fmt::Display for Json {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render())
    }
}

/// One JSON string, escaped the way RFC 8259 asks for.
fn write_text(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_name_cannot_break_the_document() {
        let document = Json::Array(vec![
            Json::Text(String::from("A\"; drop table")),
            Json::Text(String::from("back\\slash")),
            Json::Text(String::from("new\nline")),
            Json::Number(-1),
            Json::Bool(true),
            Json::Null,
        ])
        .render();
        assert_eq!(
            document,
            r#"["A\"; drop table","back\\slash","new\nline",-1,true,null]"#
        );
    }

    #[test]
    fn an_empty_array_and_an_empty_object_stay_on_one_line() {
        assert_eq!(Json::Array(Vec::new()).render_pretty(), "[]\n");
        assert_eq!(Json::Object(Vec::new()).render_pretty(), "{}\n");
    }
}
