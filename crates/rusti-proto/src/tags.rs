//! IRCv3 message tag accessors.
//!
//! Tag keys are deliberately opaque and case-sensitive. In particular, an
//! invalid/unknown key MUST NOT cause the whole message to be rejected.
//! Values decoded by this module are **untrusted**; they can include CR/LF
//! and must never be used for commands, identity, or terminal/HTML rendering.
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTag<'a> {
    pub key: &'a str,
    pub raw_value: Option<&'a str>,
}

impl<'a> RawTag<'a> {
    /// The IRCv3 protocol treats missing and empty values identically.
    pub fn normalized_raw_value(self) -> Option<&'a str> {
        match self.raw_value {
            Some("") | None => None,
            some => some,
        }
    }
}

/// Iterate without allocating, preserving odd future tag names as opaque data.
pub fn raw_tags(raw: &str) -> impl Iterator<Item = RawTag<'_>> {
    raw.split(';').map(|tag| {
        let (key, raw_value) = match tag.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (tag, None),
        };
        RawTag { key, raw_value }
    })
}

/// IRCv3 duplicate tag keys: the last occurrence wins. No trust is inferred.
pub fn last_tag<'a>(raw: &'a str, name: &str) -> Option<RawTag<'a>> {
    raw_tags(raw).filter(|tag| tag.key == name).last()
}

/// Decode IRCv3 tag escaping according to the official message-tags spec.
///
/// Unknown escapes drop only their backslash; a final backslash is dropped.
/// The result is untrusted and may contain controls such as CR or LF: never
/// insert it into a wire command, terminal, HTML, or Rust Boy trust metadata.
pub fn unescape_tag_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(':') => out.push(';'),
                Some('s') => out.push(' '),
                Some('\\') => out.push('\\'),
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_opaque_names_and_last_duplicate() {
        let raw = "foo=old;invalid@key=anything;foo=new;Foo=capital";
        assert_eq!(last_tag(raw, "foo").unwrap().raw_value, Some("new"));
        assert_eq!(last_tag(raw, "Foo").unwrap().raw_value, Some("capital"));
        assert_eq!(last_tag(raw, "invalid@key").unwrap().raw_value, Some("anything"));
        assert_eq!(last_tag(raw, "missing"), None);
    }

    #[test]
    fn missing_and_empty_tag_values_are_equivalent() {
        assert_eq!(last_tag("foo;bar=", "foo").unwrap().normalized_raw_value(), None);
        assert_eq!(last_tag("foo;bar=", "bar").unwrap().normalized_raw_value(), None);
    }

    #[test]
    fn full_ircv3_unescape_mapping() {
        let encoded = r"semi\:space\sback\\slash\rreturn\nnewline\zunknown\";
        assert_eq!(
            unescape_tag_value(encoded),
            "semi;space back\\slash\rreturn\nnewlinezunknown"
        );
    }

    #[test]
    fn unicode_values_are_not_mangled() {
        assert_eq!(unescape_tag_value("café\\s東京"), "café 東京");
    }
}
