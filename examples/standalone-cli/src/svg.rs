//! Offline SVG preview only. No browser, sockets, or live IRC input.
use rusti_adapter::micro_gui::{MicroGui, VIEW_HEIGHT, VIEW_WIDTH};

fn escape_xml(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Render a static, intentionally untrusted and offline micro-screen preview.
/// Output is an SVG document, not an interactive HTML or executable interface.
pub fn render(screen: &MicroGui) -> String {
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\">\n",
        VIEW_WIDTH, VIEW_HEIGHT, VIEW_WIDTH, VIEW_HEIGHT
    );
    svg.push_str("<rect width=\"320\" height=\"240\" fill=\"#101a12\"/>\n");
    svg.push_str("<rect width=\"320\" height=\"32\" fill=\"#25412b\"/>\n");
    svg.push_str("<rect x=\"8\" y=\"36\" width=\"304\" height=\"156\" fill=\"#17261b\" stroke=\"#63835c\"/>\n");
    for (i, label) in ["PREV", "NEXT", "UP", "DOWN"].iter().enumerate() {
        let x = i * 80;
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"196\" width=\"80\" height=\"44\" fill=\"#29472f\" stroke=\"#6e9067\"/>\n",
            x
        ));
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"222\" text-anchor=\"middle\" font-family=\"monospace\" font-size=\"12\" fill=\"#d6eed0\">{}</text>\n",
            x + 40, label
        ));
    }
    for cmd in screen.paint_text() {
        // The terminal footer is already represented by the four buttons.
        if cmd.y == 222 {
            continue;
        }
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"12\" fill=\"#b7e1ab\">{}</text>\n",
            cmd.x, cmd.y, escape_xml(&cmd.text)
        ));
    }
    svg.push_str("</svg>\n");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_text_is_escaped() {
        assert_eq!(escape_xml("<script>&\"'"), "&lt;script&gt;&amp;&quot;&apos;");
        assert_eq!(escape_xml("a\u{001b}b"), "ab");
    }

    #[test]
    fn svg_is_fixed_size_and_offline() {
        let doc = render(&MicroGui::default());
        assert!(doc.contains("viewBox=\"0 0 320 240\""));
        assert!(doc.contains("DISABLED"));
        assert!(!doc.contains("<script"));
    }
}
