use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sherlock"))
}

#[test]
fn help_and_version_exit_zero() {
    let help = bin().arg("--help").output().unwrap();
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("Sherlock Homes"));
    assert!(
        stdout.to_ascii_lowercase().contains("investigation")
            || stdout.contains("clue")
            || stdout.contains("CLUE")
    );

    let ver = bin().arg("version").output().unwrap();
    assert!(ver.status.success());
    assert!(String::from_utf8_lossy(&ver.stdout).contains("sherlock"));
}

#[test]
fn doctor_does_not_require_optional_engines() {
    let out = bin().arg("doctor").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("SHERLOCK SYSTEM DIAGNOSTICS") || text.contains("Core"));
}

#[test]
fn invalid_command_nonzero() {
    let out = bin().arg("not-a-real-command").output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.is_empty());
}

#[test]
fn findings_pdf_format_is_rejected() {
    let out = bin()
        .args(["findings", "SH-000000-XXXX", "--format", "pdf"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("sherlock report") || err.contains("does not write"));
}

#[test]
fn scan_subcommand_help() {
    for cmd in [
        "scan",
        "crawl",
        "inspect",
        "cases",
        "report",
        "auth",
        "engines",
        "config",
        "completion",
    ] {
        let out = bin().args([cmd, "--help"]).output().unwrap();
        assert!(out.status.success(), "{cmd} --help failed");
    }
}

#[test]
fn machine_json_has_no_banner() {
    let out = bin()
        .args(["--format", "json", "version"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("SHERLOCK HOMES\n"));
}
