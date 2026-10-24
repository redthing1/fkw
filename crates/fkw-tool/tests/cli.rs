use fido_key_wrap::seal;
use std::{
    ffi::OsStr,
    fs,
    process::{Command, Output},
};
fn run(dir: &std::path::Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fkw"))
        .current_dir(dir)
        .args(arguments)
        .output()
        .unwrap()
}
fn ok(dir: &std::path::Path, arguments: &[&str]) -> Output {
    let output = run(dir, arguments);
    assert!(
        output.status.success(),
        "{:?}: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
#[test]
#[allow(clippy::too_many_lines)] // One persisted lifecycle, including its failure cases.
fn complete_cli_recovery_and_method_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let plain = vec![0x5a; 100_001];
    fs::write(path.join("input"), &plain).unwrap();
    ok(path, &["recovery", "first.key"]);
    assert_eq!(fs::read(path.join("first.key")).unwrap().len(), 32);
    assert!(!run(path, &["recovery", "first.key"]).status.success());
    ok(
        path,
        &[
            "seal",
            "input",
            "-o",
            "sealed",
            "--method",
            "recovery",
            "--recovery-file",
            "first.key",
        ],
    );
    let original = seal::inspect_file(path.join("sealed")).unwrap();
    let first = original.methods().next().unwrap().id.to_string();
    assert_eq!(
        ok(path, &["open", "sealed", "--recovery-file", "first.key"]).stdout,
        plain
    );
    let listed = ok(path, &["inspect", "sealed"]);
    assert!(
        String::from_utf8(listed.stdout)
            .unwrap()
            .contains("Unverified")
    );
    ok(path, &["recovery", "second.key"]);
    ok(
        path,
        &[
            "methods",
            "add",
            "sealed",
            "-o",
            "two",
            "--method",
            "recovery",
            "--recovery-file",
            "first.key",
            "--new-recovery-file",
            "second.key",
        ],
    );
    assert!(
        !run(path, &["open", "two", "--recovery-file", "first.key"])
            .status
            .success()
    );
    let two = seal::inspect_file(path.join("two")).unwrap();
    let second = two
        .methods()
        .find(|m| m.id.to_string() != first)
        .unwrap()
        .id
        .to_string();
    ok(
        path,
        &[
            "methods",
            "remove",
            "two",
            "-o",
            "one",
            "--unlock",
            &second,
            "--remove",
            &first,
            "--recovery-file",
            "second.key",
        ],
    );
    assert_eq!(
        ok(path, &["open", "one", "--recovery-file", "second.key"]).stdout,
        plain
    );
    assert!(
        !run(
            path,
            &[
                "methods",
                "remove",
                "one",
                "-o",
                "none",
                "--remove",
                &second,
                "--recovery-file",
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
            "methods",
            "replace",
            "one",
            "-o",
            "replaced",
            "--remove",
            &second,
            "--method",
            "recovery",
            "--recovery-file",
            "second.key",
            "--new-recovery-file",
            "first.key",
        ],
    );
    let replaced = seal::inspect_file(path.join("replaced")).unwrap();
    assert_eq!(replaced.methods().len(), 1);
    assert_ne!(replaced.methods().next().unwrap().id.to_string(), second);
    assert_eq!(
        ok(path, &["open", "replaced", "--recovery-file", "first.key"]).stdout,
        plain
    );
    assert!(
        !run(
            path,
            &[
                "--application",
                "other.example",
                "open",
                "sealed",
                "--recovery-file",
                "first.key"
            ]
        )
        .status
        .success()
    );
    assert!(
        !run(
            path,
            &[
                "open",
                "sealed",
                "-o",
                "input",
                "--recovery-file",
                "first.key"
            ]
        )
        .status
        .success()
    );
    assert_eq!(fs::read(path.join("input")).unwrap(), plain);
    let mut corrupt = fs::read(path.join("sealed")).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(path.join("corrupt"), corrupt).unwrap();
    let failed = run(path, &["open", "corrupt", "--recovery-file", "first.key"]);
    assert!(!failed.status.success());
    assert_eq!(failed.stdout, Vec::<u8>::new());
    let failed = run(
        path,
        &[
            "open",
            "corrupt",
            "-o",
            "bad",
            "--recovery-file",
            "first.key",
        ],
    );
    assert!(!failed.status.success());
    assert!(!path.join("bad").exists());
    assert!(
        !fs::read_dir(path)
            .unwrap()
            .any(|entry| entry.unwrap().file_name().as_os_str() == OsStr::new("none"))
    );
}
#[test]
fn invalid_recipe_options_fail_before_any_prompt() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("input"), b"test").unwrap();
    for options in [
        ["--uv", "--method", "passphrase"],
        ["--managed", "--method", "recovery"],
    ] {
        let mut args = vec!["seal", "input", "-o", "output"];
        args.extend(options);
        let result = run(dir.path(), &args);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("require a key method"));
        assert!(!dir.path().join("output").exists());
    }
}
