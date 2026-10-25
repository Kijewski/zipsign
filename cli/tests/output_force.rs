//! `--output` must only require `--force` when the output file already exists.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

const CONTEXT: &str = "zipsign-output-force";

fn zipsign(dir: &Path, args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_zipsign"))
        .current_dir(dir)
        .args(args)
        .output()?)
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "zipsign failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_refused_exists(output: &Output) {
    assert!(!output.status.success(), "zipsign unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("output exists"),
        "unexpected error: {stderr}"
    );
}

/// Creates a key pair and a signed `.tar.gz` (the CLI does not inspect the archive content).
fn setup(dir: &Path) -> Result {
    assert_success(&zipsign(dir, &["gen-key", "priv.key", "pub.key"])?);
    fs::write(dir.join("input.tgz"), b"not really a tarball")?;
    assert_success(&zipsign(dir, &[
        "sign",
        "tar",
        "input.tgz",
        "priv.key",
        "-c",
        CONTEXT,
        "-o",
        "signed.tgz",
    ])?);
    Ok(())
}

#[test]
fn sign_output() -> Result {
    let dir = tempfile::tempdir()?;
    let dir = dir.path();
    setup(dir)?;

    // A new output file needs no `--force`.
    assert_success(&zipsign(dir, &[
        "verify",
        "tar",
        "signed.tgz",
        "pub.key",
        "-c",
        CONTEXT,
    ])?);

    // An existing output file is refused and left untouched without `--force` ...
    fs::write(dir.join("existing.tgz"), b"keep me")?;
    let sign_existing = [
        "sign",
        "tar",
        "input.tgz",
        "priv.key",
        "-c",
        CONTEXT,
        "-o",
        "existing.tgz",
    ];
    assert_refused_exists(&zipsign(dir, &sign_existing)?);
    assert_eq!(fs::read(dir.join("existing.tgz"))?, b"keep me");

    // ... and replaced with `--force`.
    assert_success(&zipsign(dir, &[&sign_existing[..], &["-f"]].concat())?);
    assert_success(&zipsign(dir, &[
        "verify",
        "tar",
        "existing.tgz",
        "pub.key",
        "-c",
        CONTEXT,
    ])?);
    Ok(())
}

#[test]
fn unsign_output() -> Result {
    let dir = tempfile::tempdir()?;
    let dir = dir.path();
    setup(dir)?;

    // A new output file needs no `--force`.
    assert_success(&zipsign(dir, &[
        "unsign",
        "tar",
        "signed.tgz",
        "-o",
        "unsigned.tgz",
    ])?);
    assert_eq!(fs::read(dir.join("unsigned.tgz"))?, b"not really a tarball");

    // An existing output file is refused and left untouched without `--force` ...
    fs::write(dir.join("existing.tgz"), b"keep me")?;
    let unsign_existing = ["unsign", "tar", "signed.tgz", "-o", "existing.tgz"];
    assert_refused_exists(&zipsign(dir, &unsign_existing)?);
    assert_eq!(fs::read(dir.join("existing.tgz"))?, b"keep me");

    // ... and replaced with `--force`.
    assert_success(&zipsign(dir, &[&unsign_existing[..], &["-f"]].concat())?);
    assert_eq!(fs::read(dir.join("existing.tgz"))?, b"not really a tarball");
    Ok(())
}
