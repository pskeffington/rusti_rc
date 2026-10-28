#![forbid(unsafe_code)]

mod svg;

fn micro_preview() -> Result<(), &'static str> {
    use rusti_adapter::micro_gui::{Key, MicroGui};
    use rusti_adapter::ChatPreviewAdapter;

    let adapter = ChatPreviewAdapter { enabled: true };
    let mut screen = MicroGui::default();
    let fixture = ":scout PRIVMSG #ops :Offline micro display fixture\\r\\n";
    let chat = adapter
        .inspect_frame(fixture)
        .map_err(|_| "invalid synthetic IRC frame")?
        .ok_or("synthetic frame was not a chat message")?;
    screen.append(&chat);
    screen.on_key(Key::Up);
    for row in screen.rows() {
        println!("{row}");
    }
    println!("Local fixture only; network and sending disabled.");
    Ok(())
}

fn micro_svg() -> Result<(), &'static str> {
    use rusti_adapter::micro_gui::MicroGui;
    use rusti_adapter::ChatPreviewAdapter;

    let adapter = ChatPreviewAdapter { enabled: true };
    let chat = adapter
        .inspect_frame(":scout PRIVMSG #ops :Offline synthetic preview\\r\\n")
        .map_err(|_| "invalid fixture")?
        .ok_or("missing fixture message")?;
    let mut screen = MicroGui::default();
    screen.append(&chat);
    print!("{}", svg::render(&screen));
    Ok(())
}

fn main() {
    if std::env::args().any(|arg| arg == "--micro-svg") {
        if let Err(message) = micro_svg() {
            eprintln!("{message}");
            std::process::exit(1);
        }
        return;
    }
    if !rusti_testkit::check_baseline_fixtures() {
        eprintln!("rusti_rc offline wire fixtures: FAIL");
        std::process::exit(1);
    }
    println!("rusti_rc offline wire fixtures: PASS (network disabled)");
    if std::env::args().any(|arg| arg == "--micro-preview") {
        if let Err(message) = micro_preview() {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}
