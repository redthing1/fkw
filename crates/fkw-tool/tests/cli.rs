use fkw::{ApplicationId, Enrollment, Method, Protector, RecoverySecret, seal};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fkw"))
        .current_dir(dir)
        .arg("--no-input")
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn ok(dir: &Path, args: &[&str]) -> Output {
    success(run(dir, args))
}
fn piped(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fkw"))
        .current_dir(dir)
        .arg("--no-input")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Drain output concurrently: a pipe may be smaller than the test payload.
    std::thread::scope(|scope| {
        scope.spawn(move || {
            stdin.write_all(input).unwrap();
        });
        child.wait_with_output().unwrap()
    })
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("input"), b"a private note\n").unwrap();
    ok(dir.path(), &["recovery", "first.key"]);
    ok(
        dir.path(),
        &[
            "seal",
            "input",
            "-w",
            "recovery",
            "-n",
            "primary",
            "-r",
            "first.key",
        ],
    );
    dir
}
fn private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn recipient_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    ok(path, &["recovery", "primary.key"]);
    ok(
        path,
        &[
            "recipient",
            "create",
            "identity.fkw",
            "-w",
            "recovery",
            "-n",
            "primary",
            "-r",
            "primary.key",
        ],
    );
    assert!(path.join("identity.fkw.pub").exists());
    dir
}

#[test]
fn recipient_workflow_reuses_seal_open_and_access() {
    let dir = recipient_fixture();
    let path = dir.path();
    let plain = vec![0x42; 131_073];
    fs::write(path.join("message"), &plain).unwrap();
    ok(path, &["seal", "message", "--to", "identity.fkw.pub"]);
    ok(
        path,
        &[
            "verify",
            "message.fkw",
            "--identity",
            "identity.fkw",
            "-r",
            "primary.key",
        ],
    );
    let opened = ok(
        path,
        &[
            "open",
            "message.fkw",
            "--identity",
            "identity.fkw",
            "-r",
            "primary.key",
            "-c",
        ],
    );
    assert_eq!(opened.stdout, plain);
    ok(path, &["recovery", "backup.key"]);
    ok(
        path,
        &[
            "access",
            "add",
            "identity.fkw",
            "-w",
            "recovery",
            "-n",
            "backup",
            "-r",
            "primary.key",
            "--new-recovery-file",
            "backup.key",
        ],
    );
    ok(
        path,
        &[
            "recipient",
            "public",
            "identity.fkw",
            "-u",
            "backup",
            "-r",
            "backup.key",
            "-o",
            "again.pub",
        ],
    );
    assert_eq!(
        fs::read(path.join("identity.fkw.pub")).unwrap(),
        fs::read(path.join("again.pub")).unwrap()
    );
    ok(
        path,
        &[
            "open",
            "message.fkw",
            "--identity",
            "identity.fkw",
            "-u",
            "backup",
            "-r",
            "backup.key",
            "-o",
            "opened",
        ],
    );
    assert_eq!(fs::read(path.join("opened")).unwrap(), plain);
    private(&path.join("opened"));
}

#[test]
fn recipient_transport_and_failed_authentication() {
    let dir = recipient_fixture();
    let path = dir.path();
    let armored = success(piped(
        path,
        &["seal", "--to", "identity.fkw.pub", "--armor"],
        b"piped message",
    ));
    let reopened = success(piped(
        path,
        &[
            "open",
            "--identity",
            "identity.fkw",
            "-r",
            "primary.key",
            "-c",
        ],
        &armored.stdout,
    ));
    assert_eq!(reopened.stdout, b"piped message");
    fs::write(path.join("message"), vec![0x42; 131_073]).unwrap();
    ok(path, &["seal", "message", "--to", "identity.fkw.pub"]);
    let mut changed = fs::read(path.join("message.fkw")).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(path.join("corrupt.fkw"), changed).unwrap();
    let rejected = run(
        path,
        &[
            "open",
            "corrupt.fkw",
            "--identity",
            "identity.fkw",
            "-r",
            "primary.key",
            "-c",
        ],
    );
    assert!(!rejected.status.success());
    assert_eq!(rejected.stdout, [] as [u8; 0]);
    assert_eq!(
        run(path, &["seal", "message", "--to", "again.pub", "-w", "key"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn offline_signature_workflow_and_expected_purpose() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let vectors = include_str!("../../../test-vectors/public-key-1.txt");
    for (field, file) in [
        ("credential", "signer"),
        ("verification_key", "signer.pub"),
        ("signing_message", "manifest"),
        ("signature", "manifest.sig"),
    ] {
        let hex = vectors
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}=")))
            .unwrap();
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        fs::write(path.join(file), bytes).unwrap();
    }
    ok(path, &["signer", "public", "signer", "-o", "exported.pub"]);
    assert_eq!(
        fs::read(path.join("exported.pub")).unwrap(),
        fs::read(path.join("signer.pub")).unwrap()
    );
    ok(
        path,
        &[
            "verify",
            "manifest",
            "--signature",
            "manifest.sig",
            "--key",
            "signer.pub",
            "--purpose",
            "release",
        ],
    );
    assert!(
        !run(
            path,
            &[
                "verify",
                "manifest",
                "--signature",
                "manifest.sig",
                "--key",
                "signer.pub"
            ]
        )
        .status
        .success()
    );
    fs::write(path.join("manifest"), b"changed").unwrap();
    assert!(
        !run(
            path,
            &[
                "verify",
                "manifest",
                "--signature",
                "manifest.sig",
                "--key",
                "signer.pub",
                "--purpose",
                "release"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        run(path, &["verify", "manifest", "--signature", "manifest.sig"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn file_defaults_outputs_and_help() {
    let dir = fixture();
    let path = dir.path();
    let plain = fs::read(path.join("input")).unwrap();
    assert_eq!(fs::read(path.join("first.key")).unwrap().len(), 32);
    private(&path.join("first.key"));
    private(&path.join("input.fkw"));
    let help = ok(path, &["--help"]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: fkw"));
    assert!(String::from_utf8_lossy(&ok(path, &["--version"]).stdout).starts_with("fkw "));
    let missing = run(path, &["open", "input.fkw", "-r", "first.key"]);
    assert!(!missing.status.success());
    assert_eq!(missing.stdout, b"");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--output"));
    ok(
        path,
        &["open", "input.fkw", "-r", "first.key", "-o", "restored"],
    );
    assert_eq!(fs::read(path.join("restored")).unwrap(), plain);
    private(&path.join("restored"));
    assert_eq!(
        ok(path, &["open", "input.fkw", "-r", "first.key", "-c"]).stdout,
        plain
    );
    assert_eq!(
        ok(path, &["verify", "input.fkw", "-r", "first.key"]).stdout,
        b""
    );
    let info = ok(path, &["info", "input.fkw"]);
    let info = String::from_utf8(info.stdout).unwrap();
    assert!(info.contains("Unverified") && info.contains("primary") && info.contains("recovery"));
    for args in [
        vec!["recovery", "first.key"],
        vec!["seal", "input", "-w", "recovery", "-r", "first.key"],
        vec!["open", "input.fkw", "-r", "first.key", "-o", "input"],
    ] {
        assert!(!run(path, &args).status.success());
    }
    assert_eq!(fs::read(path.join("input")).unwrap(), plain);
}

#[test]
fn access_defaults_update_the_file_and_name_repeated_methods() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    ok(path, &["recovery", "key"]);
    for transport in ["-c", "--armor"] {
        let sealed = success(piped(
            path,
            &["seal", transport, "-w", "recovery", "-r", "key"],
            b"a private note",
        ))
        .stdout;
        fs::write(path.join("sealed"), &sealed).unwrap();
        for _ in 0..2 {
            ok(
                path,
                &[
                    "access", "add", "sealed", "-u", "recovery", "-w", "recovery", "-r", "key",
                ],
            );
        }
        let updated = fs::read(path.join("sealed")).unwrap();
        assert_eq!(updated.starts_with(b"fkw:"), transport == "--armor");
        private(&path.join("sealed"));
        assert_eq!(
            ok(
                path,
                &["open", "sealed", "-c", "-u", "recovery-3", "-r", "key"]
            )
            .stdout,
            b"a private note"
        );
        // Explicit labels still reject collisions and leave the input intact.
        assert!(
            !run(
                path,
                &[
                    "access",
                    "add",
                    "sealed",
                    "-u",
                    "recovery",
                    "-w",
                    "recovery",
                    "-n",
                    "recovery-2",
                    "-r",
                    "key",
                ],
            )
            .status
            .success()
        );
        assert_eq!(fs::read(path.join("sealed")).unwrap(), updated);
        ok(
            path,
            &[
                "access",
                "replace",
                "sealed",
                "recovery-2",
                "-u",
                "recovery",
                "-w",
                "recovery",
                "-r",
                "key",
            ],
        );
        ok(
            path,
            &[
                "access",
                "remove",
                "sealed",
                "recovery",
                "-u",
                "recovery-2",
                "-r",
                "key",
            ],
        );
        let info = ok(path, &["info", "sealed"]);
        let info = String::from_utf8(info.stdout).unwrap();
        assert!(info.contains("\"recovery-2\"") && info.contains("\"recovery-3\""));
        assert!(!info.contains("\"recovery\""));
        ok(path, &["verify", "sealed", "-u", "recovery-2", "-r", "key"]);
    }
    let missing = run(path, &["access", "add", "-", "-w", "recovery", "-r", "key"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("stdin require -o FILE"));
    assert!(!path.join("-").exists());
}

#[test]
fn removal_in_place_requires_unlocking_through_a_surviving_method() {
    let dir = fixture();
    let path = dir.path();
    ok(
        path,
        &[
            "access",
            "add",
            "input.fkw",
            "-w",
            "recovery",
            "-r",
            "first.key",
        ],
    );
    let original = fs::read(path.join("input.fkw")).unwrap();
    let result = run(
        path,
        &[
            "access",
            "remove",
            "input.fkw",
            "primary",
            "-u",
            "primary",
            "-r",
            "first.key",
        ],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("method you are keeping"));
    assert_eq!(fs::read(path.join("input.fkw")).unwrap(), original);
    ok(
        path,
        &[
            "access",
            "remove",
            "input.fkw",
            "primary",
            "-u",
            "recovery",
            "-r",
            "first.key",
        ],
    );
    ok(path, &["verify", "input.fkw", "-r", "first.key"]);
}

#[test]
fn large_binary_and_armored_pipes_share_the_container() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    ok(path, &["recovery", "key"]);
    let plain = vec![0xa5; 2 * 1024 * 1024 + 7];
    for transport in [vec!["-c"], vec!["--armor"]] {
        let mut args = vec!["seal", "-", "-w", "recovery", "-r", "key"];
        args.extend(transport);
        let sealed = success(piped(path, &args, &plain)).stdout;
        let opened = success(piped(path, &["open", "-c", "-r", "key"], &sealed));
        assert_eq!(opened.stdout, plain);
        assert!(
            success(piped(path, &["info"], &sealed))
                .stdout
                .starts_with(b"Unverified")
        );
        assert_eq!(
            success(piped(path, &["verify", "-r", "key"], &sealed)).stdout,
            b""
        );
        if sealed.starts_with(b"fkw:") {
            let mut wrapped = b"fkw: \n".to_vec();
            for chunk in sealed[4..].chunks(71) {
                wrapped.extend_from_slice(chunk);
                wrapped.extend_from_slice(b"\r\n \t");
            }
            fs::write(path.join("armored"), &wrapped).unwrap();
            assert_eq!(
                ok(path, &["open", "armored", "-c", "-r", "key"]).stdout,
                plain
            );
            wrapped.extend_from_slice(b"!");
            let bad = piped(path, &["open", "-c", "-r", "key"], &wrapped);
            assert!(!bad.status.success());
            assert_eq!(bad.stdout, b"");
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One persisted method lifecycle, including old copies and ciphertext.
fn access_lifecycle_selects_labels_and_ids_and_preserves_payload() {
    let dir = fixture();
    let path = dir.path();
    ok(path, &["recovery", "second.key"]);
    let original = seal::inspect_file(path.join("input.fkw")).unwrap();
    let first = original.methods().next().unwrap().id.to_string();
    ok(
        path,
        &[
            "access",
            "add",
            "input.fkw",
            "-o",
            "two",
            "-w",
            "recovery",
            "-n",
            "backup",
            "-r",
            "first.key",
            "--new-recovery-file",
            "second.key",
        ],
    );
    let two = seal::inspect_file(path.join("two")).unwrap();
    let second = two
        .methods()
        .find(|m| m.label == "backup")
        .unwrap()
        .id
        .to_string();
    let original_bytes = fs::read(path.join("input.fkw")).unwrap();
    let two_bytes = fs::read(path.join("two")).unwrap();
    // The mutable header has a different length; the nonce and payload are identical.
    assert_eq!(
        &original_bytes[9 + original.to_bytes().len()..],
        &two_bytes[9 + two.to_bytes().len()..]
    );
    let plain = fs::read(path.join("input")).unwrap();
    assert!(
        !run(path, &["open", "two", "-c", "-r", "first.key"])
            .status
            .success()
    );
    assert_eq!(
        ok(
            path,
            &["open", "two", "-c", "-u", "primary", "-r", "first.key"]
        )
        .stdout,
        plain
    );
    assert_eq!(
        ok(
            path,
            &["open", "two", "-c", "-u", &second[..8], "-r", "second.key"]
        )
        .stdout,
        plain
    );
    let duplicate = run(
        path,
        &[
            "access",
            "add",
            "two",
            "-o",
            "duplicate",
            "-w",
            "recovery",
            "-n",
            "backup",
            "-u",
            "primary",
            "-r",
            "first.key",
        ],
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("name already exists"));
    ok(
        path,
        &[
            "access",
            "remove",
            "two",
            "primary",
            "-o",
            "one",
            "-u",
            "backup",
            "-r",
            "second.key",
        ],
    );
    assert_eq!(
        ok(path, &["open", "one", "-c", "-r", "second.key"]).stdout,
        plain
    );
    assert!(
        !run(
            path,
            &["open", "one", "-c", "-u", &first, "-r", "first.key"]
        )
        .status
        .success()
    );
    assert!(
        !run(
            path,
            &[
                "access",
                "remove",
                "one",
                "backup",
                "-o",
                "none",
                "-r",
                "second.key"
            ]
        )
        .status
        .success()
    );
    assert!(!path.join("none").exists());
    ok(
        path,
        &[
            "access",
            "replace",
            "one",
            "backup",
            "-o",
            "replaced",
            "-w",
            "recovery",
            "-r",
            "second.key",
            "--new-recovery-file",
            "first.key",
        ],
    );
    let replaced = seal::inspect_file(path.join("replaced")).unwrap();
    assert_eq!(replaced.methods().len(), 1);
    assert_eq!(replaced.methods().next().unwrap().label, "backup");
    assert_ne!(replaced.methods().next().unwrap().id.to_string(), second);
    assert_eq!(
        ok(path, &["open", "replaced", "-c", "-r", "first.key"]).stdout,
        plain
    );
    // Removing a route from the new file does not revoke older copies.
    assert_eq!(
        ok(
            path,
            &["open", "two", "-c", "-u", "primary", "-r", "first.key"]
        )
        .stdout,
        plain
    );
    assert_eq!(fs::read(path.join("input.fkw")).unwrap(), original_bytes);
}

#[test]
fn damaged_files_release_no_plaintext_or_new_access() {
    let dir = fixture();
    let path = dir.path();
    let sealed = fs::read(path.join("input.fkw")).unwrap();
    let mut changed = sealed.clone();
    *changed.last_mut().unwrap() ^= 1;
    let mut trailing = sealed.clone();
    trailing.push(0);
    for bytes in [changed, sealed[..sealed.len() - 1].to_vec(), trailing] {
        fs::write(path.join("bad"), &bytes).unwrap();
        for args in [
            vec!["open", "bad", "-c", "-r", "first.key"],
            vec!["open", "bad", "-o", "plaintext", "-r", "first.key"],
            vec!["verify", "bad", "-r", "first.key"],
            // A passphrase prompt must not happen before full verification.
            vec![
                "access",
                "add",
                "bad",
                "-o",
                "updated",
                "-w",
                "passphrase",
                "-r",
                "first.key",
            ],
            vec!["access", "add", "bad", "-w", "recovery", "-r", "first.key"],
        ] {
            let result = run(path, &args);
            assert!(!result.status.success());
            assert_eq!(result.stdout, b"");
            assert!(!String::from_utf8_lossy(&result.stderr).contains("Terminal input"));
        }
        assert!(!path.join("plaintext").exists());
        assert!(!path.join("updated").exists());
        assert_eq!(fs::read(path.join("bad")).unwrap(), bytes);
        assert!(!fs::read_dir(path).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fkw-")
        }));
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One snapshot lifecycle: reseal, restore, and reject unrelated data.
fn retained_snapshots_resume_without_reenrollment() {
    let dir = fixture();
    let path = dir.path();
    let original = seal::inspect_file(path.join("input.fkw")).unwrap();
    fs::write(path.join("envelope"), original.to_bytes()).unwrap();
    ok(
        path,
        &[
            "seal",
            "input",
            "-o",
            "resumed",
            "--resume",
            "envelope",
            "-r",
            "first.key",
        ],
    );
    let resumed = seal::inspect_file(path.join("resumed")).unwrap();
    assert_eq!(resumed.to_bytes(), original.to_bytes());
    // Fresh stream material even though the enrollment is reused.
    assert_ne!(
        fs::read(path.join("resumed")).unwrap(),
        fs::read(path.join("input.fkw")).unwrap()
    );
    assert_eq!(
        ok(path, &["open", "resumed", "-c", "-r", "first.key"]).stdout,
        fs::read(path.join("input")).unwrap()
    );
    ok(
        path,
        &[
            "access",
            "add",
            "input.fkw",
            "-o",
            "added",
            "-w",
            "recovery",
            "-n",
            "backup",
            "-r",
            "first.key",
        ],
    );
    let added = seal::inspect_file(path.join("added")).unwrap();
    fs::write(path.join("envelope"), added.to_bytes()).unwrap();
    ok(
        path,
        &[
            "access",
            "restore",
            "input.fkw",
            "--envelope",
            "envelope",
            "-o",
            "restored",
            "-u",
            "backup",
            "-r",
            "first.key",
        ],
    );
    assert_eq!(
        fs::read(path.join("restored")).unwrap(),
        fs::read(path.join("added")).unwrap()
    );
    ok(
        path,
        &[
            "seal",
            "input",
            "-o",
            "unrelated",
            "-w",
            "recovery",
            "-r",
            "first.key",
        ],
    );
    assert!(
        !run(
            path,
            &[
                "access",
                "restore",
                "unrelated",
                "--envelope",
                "envelope",
                "-o",
                "wrong",
                "-u",
                "backup",
                "-r",
                "first.key"
            ]
        )
        .status
        .success()
    );
    assert!(!path.join("wrong").exists());
    ok(
        path,
        &[
            "access",
            "restore",
            "input.fkw",
            "--envelope",
            "envelope",
            "-u",
            "backup",
            "-r",
            "first.key",
        ],
    );
    assert_eq!(
        fs::read(path.join("input.fkw")).unwrap(),
        fs::read(path.join("added")).unwrap()
    );
}

#[test]
fn invalid_options_and_untrusted_metadata_fail_without_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    fs::write(path.join("input"), b"test").unwrap();
    for options in [
        vec!["--uv", "-w", "passphrase"],
        vec!["--managed", "-w", "recovery"],
        vec!["--store-access", "standard", "-w", "recovery"],
        vec!["-w", "recovery", "-n", ""],
        vec!["--resume", "missing", "-w", "recovery"],
        vec!["--text", "actual secret must not be an argument"],
    ] {
        let mut args = vec!["seal", "input", "-o", "output"];
        args.extend(options);
        assert!(!run(path, &args).status.success());
        assert!(!path.join("output").exists());
    }
    let mut secret = RecoverySecret::generate().unwrap();
    let foreign = Protector::new(ApplicationId::new("other.example").unwrap());
    let key = foreign
        .create(
            &Enrollment::new(Method::RecoverySecret, "foreign").unwrap(),
            &mut secret,
        )
        .unwrap();
    seal::seal_file(&key, path.join("input"), path.join("foreign")).unwrap();
    let result = run(path, &["open", "foreign", "-c"]);
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("supply --recovery-file"));
    fs::write(path.join("oversized"), vec![0; 65_537]).unwrap();
    assert!(
        !run(
            path,
            &["seal", "input", "-o", "output", "--resume", "oversized"]
        )
        .status
        .success()
    );
}

#[cfg(unix)]
#[test]
fn recovery_permissions_and_symlink_destinations_are_enforced() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = fixture();
    let path = dir.path();
    fs::set_permissions(path.join("first.key"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !run(path, &["open", "input.fkw", "-c", "-r", "first.key"])
            .status
            .success()
    );
    fs::set_permissions(path.join("first.key"), fs::Permissions::from_mode(0o600)).unwrap();
    for size in [31, 33] {
        fs::write(path.join("first.key"), vec![0; size]).unwrap();
        let output = run(path, &["open", "input.fkw", "-c", "-r", "first.key"]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 32 bytes"));
    }
    symlink("missing", path.join("linked")).unwrap();
    assert!(!run(path, &["recovery", "linked"]).status.success());
    assert!(
        !run(path, &["seal", "input", "-o", "linked", "-w", "recovery"])
            .status
            .success()
    );
    assert!(!path.join("missing").exists());
    symlink("input.fkw", path.join("linked-input")).unwrap();
    let original = fs::read(path.join("input.fkw")).unwrap();
    let result = run(path, &["access", "add", "linked-input", "-w", "recovery"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("regular file"));
    assert!(
        fs::symlink_metadata(path.join("linked-input"))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(fs::read(path.join("input.fkw")).unwrap(), original);
}
