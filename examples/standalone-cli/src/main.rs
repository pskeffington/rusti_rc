#![forbid(unsafe_code)]

fn main() {
    if rusti_testkit::check_baseline_fixtures() {
        println!("rusti_rc offline wire fixtures: PASS (network disabled)");
    } else {
        eprintln!("rusti_rc offline wire fixtures: FAIL");
        std::process::exit(1);
    }
}
