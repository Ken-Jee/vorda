#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

const ARTIFACT: &[u8] = b"#!/bin/sh\nprintf '%s\n' \"$@\"\n";
const PLACEHOLDER_KEY: &str = "untrusted comment: PLACEHOLDER release key\nPLACEHOLDER-NOT-A-KEY\n";

struct Fixture {
    temp: tempfile::TempDir,
    home: PathBuf,
    prefix: PathBuf,
    tools: PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home with spaces");
        let prefix = home.join(".local");
        let tools = temp.path().join("tools");
        link_tools(
            &tools,
            &[
                "bash",
                "mkdir",
                "mktemp",
                "rmdir",
                "cp",
                "sha256sum",
                "tr",
                "chmod",
                "mv",
                "rm",
            ],
        );
        let binary = temp.path().join("artifact with spaces");
        fs::write(&binary, ARTIFACT).unwrap();
        Self {
            temp,
            home,
            prefix,
            tools,
            binary,
        }
    }

    fn install(&self) -> Output {
        self.install_with(&[])
    }

    fn install_with(&self, signature_and_key: &[&Path]) -> Output {
        let digest = format!("{:x}", Sha256::digest(ARTIFACT));
        Command::new(self.tools.join("bash"))
            .arg(repo().join("rust/release/install-native.sh"))
            .arg(&self.binary)
            .arg(digest)
            .arg(&self.prefix)
            .args(signature_and_key)
            .env("PATH", &self.tools)
            .output()
            .unwrap()
    }

    fn unit(&self, name: &str) -> PathBuf {
        let source = fs::read_to_string(repo().join("packaging/linking").join(name)).unwrap();
        let unit = self.temp.path().join(name);
        fs::write(&unit, source.replace("%h", self.home.to_str().unwrap())).unwrap();
        unit
    }

    fn verify(&self, unit: &Path) -> Output {
        Command::new("systemd-analyze")
            .args(["verify", unit.to_str().unwrap()])
            .output()
            .expect("systemd-analyze is required for installer verification")
    }
}

/// A directory holding only `names`, linked from PATH, to run scripts with a minimal PATH.
fn link_tools(tools: &Path, names: &[&str]) {
    fs::create_dir(tools).unwrap();
    let path = std::env::var_os("PATH").unwrap();
    for name in names {
        let source = std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
            .unwrap();
        symlink(source, tools.join(name)).unwrap();
    }
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn installs_with_spaces_and_minimal_path_and_units_verify() {
    let f = Fixture::new();
    let installed = f.install();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(!f.tools.join("python3").exists());
    let hub = f.unit("vorda-hub.service");
    let verified = f.verify(&hub);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let unit = fs::read_to_string(&hub).unwrap();
    let command = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .unwrap();
    let parts: Vec<_> = command.split('"').collect();
    assert_eq!(parts.len(), 9);
    let args: Vec<&str> = parts[2]
        .split_whitespace()
        .chain([parts[3]])
        .chain(parts[4].split_whitespace())
        .chain([parts[5]])
        .chain(parts[6].split_whitespace())
        .chain([parts[7]])
        .collect();
    let output = Command::new(parts[1])
        .args(args)
        .env("PATH", &f.tools)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let args: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        args,
        [
            "link",
            "--db",
            &f.home
                .join(".local/state/vorda/hub.db")
                .display()
                .to_string(),
            "serve",
            "--bind",
            "0.0.0.0",
            "--cert",
            &f.home.join(".config/vorda/hub.crt").display().to_string(),
            "--key",
            &f.home.join(".config/vorda/hub.key").display().to_string()
        ]
    );
    let wrapper = f.prefix.join("bin/vorda-send");
    fs::write(&wrapper, ARTIFACT).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["vorda-send.service", "vorda-send.timer"] {
        let verified = f.verify(&f.unit(name));
        assert!(
            verified.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
    }
}

#[test]
fn missing_executable_fails_unit_verification() {
    let f = Fixture::new();
    let verified = f.verify(&f.unit("vorda-hub.service"));
    assert!(!verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stderr)
        .contains(&f.prefix.join("bin/vorda").display().to_string()));
}

#[test]
fn checksum_mismatch_preserves_installed_bytes() {
    let f = Fixture::new();
    assert!(f.install().status.success());
    fs::write(&f.binary, b"rejected replacement").unwrap();
    let rejected = f.install();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("checksum mismatch"));
    assert_eq!(fs::read(f.prefix.join("bin/vorda")).unwrap(), ARTIFACT);
}

#[test]
fn lock_left_by_a_killed_install_is_reclaimed_but_a_live_one_is_not() {
    let f = Fixture::new();
    let lock = f.prefix.join("bin/.vorda-install.lock");
    fs::create_dir_all(&lock).unwrap();
    let mut exited = Command::new(f.tools.join("bash"))
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let pid = exited.id();
    exited.wait().unwrap();
    fs::write(lock.join("pid"), format!("{pid}\n")).unwrap();
    let reclaimed = f.install();
    assert!(
        reclaimed.status.success(),
        "{}",
        String::from_utf8_lossy(&reclaimed.stderr)
    );
    assert!(!lock.exists());
    fs::create_dir_all(&lock).unwrap();
    fs::write(lock.join("pid"), format!("{}\n", std::process::id())).unwrap();
    let held = f.install();
    assert!(!held.status.success());
    assert!(String::from_utf8_lossy(&held.stderr).contains("owns the install lock"));
    assert_eq!(
        fs::read_to_string(lock.join("pid")).unwrap(),
        format!("{}\n", std::process::id())
    );
}

#[test]
fn lock_without_a_usable_owner_pid_is_refused() {
    let f = Fixture::new();
    let lock = f.prefix.join("bin/.vorda-install.lock");
    // No pid (a lock from the older script), an empty pid, garbage, and pid 1: alive but not ours
    // to signal, which must not look like an exited owner.
    for pid in [None, Some(""), Some("not-a-pid\n"), Some("1\n")] {
        fs::create_dir_all(&lock).unwrap();
        if let Some(pid) = pid {
            fs::write(lock.join("pid"), pid).unwrap();
        }
        let refused = f.install();
        assert_eq!(refused.status.code(), Some(2), "pid {pid:?}");
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("owns the install lock"),
            "pid {pid:?}"
        );
        assert!(lock.is_dir(), "pid {pid:?}");
        let _ = fs::remove_file(lock.join("pid"));
        fs::remove_dir(&lock).unwrap();
    }
}

#[test]
fn unwritable_bin_reports_the_real_error_not_a_phantom_lock() {
    let f = Fixture::new();
    let bin = f.prefix.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
    let writable = fs::write(bin.join("probe"), b"").is_ok();
    let refused = f.install();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    if writable {
        return; // running as a user who ignores directory modes, such as root
    }
    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("ermission denied"), "{stderr}");
    assert!(!stderr.contains("owns the install lock"), "{stderr}");
}

fn release_fixture(name: &str) -> PathBuf {
    repo().join("rust/tests/fixtures/release").join(name)
}

impl Fixture {
    /// A stand-in `minisign` that records its arguments and exits with `code`.
    fn minisign(&self, code: i32) -> PathBuf {
        let calls = self.temp.path().join("minisign-calls");
        let stub = self.tools.join("minisign");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit {code}\n",
            calls.display()
        );
        fs::write(&stub, script).unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        calls
    }
}

#[test]
fn signed_install_checks_the_signature_with_minisign_and_keeps_it_beside_the_executable() {
    let f = Fixture::new();
    let (sig, key) = (
        release_fixture("payload.minisig"),
        release_fixture("release.pub"),
    );
    let calls = f.minisign(0);
    let installed = f.install_with(&[&sig, &key]);
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let calls = fs::read_to_string(calls).unwrap();
    let calls: Vec<&str> = calls.lines().collect();
    for flag in ["-V", "-q"] {
        assert!(calls.contains(&flag), "{calls:?}");
    }
    let after = |flag: &str| calls[calls.iter().position(|a| *a == flag).unwrap() + 1];
    assert_eq!(after("-p"), key.to_str().unwrap());
    assert_eq!(after("-x"), sig.to_str().unwrap());
    assert_eq!(fs::read(f.prefix.join("bin/vorda")).unwrap(), ARTIFACT);
    assert_eq!(
        fs::read(f.prefix.join("bin/vorda.minisig")).unwrap(),
        fs::read(&sig).unwrap()
    );
    // A later unsigned install must not leave the old signature claiming the new bytes.
    assert!(f.install().status.success());
    assert!(!f.prefix.join("bin/vorda.minisig").exists());
}

#[test]
fn signed_install_refuses_a_bad_signature_missing_minisign_or_the_placeholder_key() {
    let sig = release_fixture("payload.minisig");
    let key = release_fixture("release.pub");
    let f = Fixture::new();
    let refused = f.install_with(&[&sig, &key]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("minisign is required"));
    f.minisign(1);
    let refused = f.install_with(&[&sig, &key]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("signature check failed"));
    f.minisign(0);
    let placeholder = f.temp.path().join("placeholder.pub");
    fs::write(&placeholder, PLACEHOLDER_KEY).unwrap();
    let refused = f.install_with(&[&sig, &placeholder]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("placeholder"));
    assert!(!f.prefix.join("bin/vorda").exists());
    assert!(!f.prefix.join("bin/vorda.minisig").exists());
}

#[test]
fn reinstalling_with_the_installed_signature_keeps_it() {
    let f = Fixture::new();
    let (sig, key) = (
        release_fixture("payload.minisig"),
        release_fixture("release.pub"),
    );
    f.minisign(0);
    assert!(f.install_with(&[&sig, &key]).status.success());
    let installed = f.prefix.join("bin/vorda.minisig");
    let again = f.install_with(&[&installed, &key]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(fs::read(&installed).unwrap(), fs::read(&sig).unwrap());
}

/// `sign-native.sh` beside a real-looking public key, a package with one executable, and a
/// stand-in `minisign` whose signing writes `FILE.minisig` and whose check exits `verify`.
/// `secrets` is where the key and password come from: "env", "store" (a stand-in
/// `VORDA_SECRET_INJECTOR` that only knows the items `test-key` and `test-password`),
/// "store-unnamed" (the injector without the item-name variables) or "none".
fn sign(secrets: &str, placeholder: bool, verify: i32) -> (Output, Vec<String>, usize) {
    let temp = tempfile::tempdir().unwrap();
    let release = temp.path().join("release");
    fs::create_dir(&release).unwrap();
    fs::copy(
        repo().join("rust/release/sign-native.sh"),
        release.join("sign-native.sh"),
    )
    .unwrap();
    if placeholder {
        fs::write(release.join("vorda-release.pub"), PLACEHOLDER_KEY).unwrap();
    } else {
        fs::copy(
            release_fixture("release.pub"),
            release.join("vorda-release.pub"),
        )
        .unwrap();
    }
    let package = temp.path().join("package");
    fs::create_dir(&package).unwrap();
    fs::write(
        package.join("vorda-0.1.0-x86_64-unknown-linux-gnu"),
        ARTIFACT,
    )
    .unwrap();
    fs::write(package.join("SHA256SUMS"), "sums\n").unwrap();
    let minisign = temp.path().join("minisign");
    fs::write(&minisign, format!("#!/bin/sh\nif [ \"$1\" = -S ]; then\n  cat >/dev/null\n  m=\n  for a; do [ -n \"$m\" ] && : > \"$a.minisig\"; [ \"$a\" = -m ] && m=1; done\n  exit 0\nfi\nexit {verify}\n")).unwrap();
    fs::set_permissions(&minisign, fs::Permissions::from_mode(0o755)).unwrap();
    let tmp = temp.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    // INJECTOR ITEM --env VAR -- CMD...: sets VAR and runs CMD.
    let injector = temp.path().join("injector");
    fs::write(
        &injector,
        "#!/bin/sh\ncase $1 in test-key|test-password) ;; *) exit 3 ;; esac\nvar=$3\nshift 4\nexport \"$var=from the secret store\"\nexec \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&injector, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = Command::new("bash");
    command
        .arg(release.join("sign-native.sh"))
        .arg(&minisign)
        .arg(&package)
        .env("TMPDIR", &tmp)
        .env_remove("RUNNER_TEMP")
        .env_remove("VORDA_SECRET_INJECTOR")
        .env_remove("VORDA_MINISIGN_SECRET_KEY")
        .env_remove("VORDA_MINISIGN_PASSWORD")
        .env_remove("VORDA_MINISIGN_KEY_ITEM")
        .env_remove("VORDA_MINISIGN_PASSWORD_ITEM");
    if secrets.starts_with("store") {
        command.env("VORDA_SECRET_INJECTOR", &injector);
    }
    if secrets == "store" {
        command
            .env("VORDA_MINISIGN_KEY_ITEM", "test-key")
            .env("VORDA_MINISIGN_PASSWORD_ITEM", "test-password");
    }
    if secrets == "env" {
        command
            .env("VORDA_MINISIGN_SECRET_KEY", "secret key text")
            .env("VORDA_MINISIGN_PASSWORD", "password");
    }
    let output = command.output().unwrap();
    let mut signatures: Vec<_> = fs::read_dir(&package)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".minisig"))
        .collect();
    signatures.sort();
    (output, signatures, fs::read_dir(&tmp).unwrap().count())
}

#[test]
fn signing_leaves_signatures_only_when_every_one_verifies() {
    for secrets in ["env", "store"] {
        let (signed, signatures, temp_files) = sign(secrets, false, 0);
        assert_eq!(
            signed.status.code(),
            Some(0),
            "{secrets}: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
        assert_eq!(
            signatures,
            [
                "SHA256SUMS.minisig",
                "vorda-0.1.0-x86_64-unknown-linux-gnu.minisig"
            ],
            "{secrets}"
        );
        assert_eq!(temp_files, 0, "{secrets}: the secret key file is removed");
    }
    for (secrets, placeholder, verify, code) in [
        ("none", false, 0, 2),
        ("env", true, 0, 2),
        ("store", true, 0, 2),
        ("store-unnamed", false, 0, 2),
        ("env", false, 1, 1),
    ] {
        let (output, signatures, temp_files) = sign(secrets, placeholder, verify);
        let case = format!("secrets {secrets} placeholder {placeholder} verify {verify}");
        assert_eq!(output.status.code(), Some(code), "{case}");
        assert_eq!(signatures, Vec::<String>::new(), "{case}");
        assert_eq!(temp_files, 0, "{case}");
    }
}

/// One package directory per target, made by `package-native.sh` as a release build would.
fn packages(temp: &Path, targets: &[&str]) -> Vec<PathBuf> {
    targets
        .iter()
        .map(|target| {
            let package = temp.join(format!("package-{target}"));
            let packaged = Command::new("bash")
                .arg(repo().join("rust/release/package-native.sh"))
                .arg(temp.join("artifact"))
                .args(["0.2.0", target])
                .arg(&package)
                .output()
                .unwrap();
            assert!(
                packaged.status.success(),
                "{}",
                String::from_utf8_lossy(&packaged.stderr)
            );
            package
        })
        .collect()
}

fn combine(output: &Path, packages: &[PathBuf]) -> Output {
    Command::new("bash")
        .arg(repo().join("rust/release/combine-native.sh"))
        .arg(output)
        .args(packages)
        .output()
        .unwrap()
}

const MUSL: [&str; 2] = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];

#[test]
fn combining_lists_every_build_and_the_installer_in_one_checksum_file() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("artifact"), ARTIFACT).unwrap();
    let mut targets = MUSL.to_vec();
    targets.push("x86_64-unknown-linux-gnu");
    let packages = packages(temp.path(), &targets);
    let release = temp.path().join("release");
    let combined = combine(&release, &packages);
    assert!(
        combined.status.success(),
        "{}",
        String::from_utf8_lossy(&combined.stderr)
    );
    let sums = fs::read_to_string(release.join("SHA256SUMS")).unwrap();
    let names: Vec<&str> = sums
        .lines()
        .map(|l| l.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(
        names,
        [
            "install.sh",
            "vorda-0.2.0-aarch64-unknown-linux-musl",
            "vorda-0.2.0-x86_64-unknown-linux-gnu",
            "vorda-0.2.0-x86_64-unknown-linux-musl",
        ]
    );
    for line in sums.lines() {
        let (digest, name) = line.split_once("  ").unwrap();
        let bytes = fs::read(release.join(name)).unwrap();
        assert_eq!(digest, format!("{:x}", Sha256::digest(bytes)), "{name}");
    }

    // An executable that no longer matches its package checksums is refused, with no partial output.
    fs::write(
        packages[1].join("vorda-0.2.0-aarch64-unknown-linux-musl"),
        b"changed",
    )
    .unwrap();
    let refused = combine(&temp.path().join("refused"), &packages);
    assert_eq!(refused.status.code(), Some(1));
    assert!(!temp.path().join("refused").exists());
}

/// Runs `install.sh` offline from `release` with only `tools` on PATH.
fn run_installer(release: &Path, tools: &Path, dir: &Path) -> Output {
    Command::new(tools.join("sh"))
        .arg(repo().join("install.sh"))
        .env_clear()
        .env("PATH", tools)
        .env("HOME", dir)
        .env("VORDA_INSTALL_FROM", release)
        .env("VORDA_INSTALL_DIR", dir.join("bin"))
        .env("VORDA_NO_MODIFY_PATH", "1")
        .output()
        .unwrap()
}

#[test]
fn installer_checks_the_release_signature_when_minisign_is_available() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("artifact"), ARTIFACT).unwrap();
    let release = temp.path().join("release");
    assert!(combine(&release, &packages(temp.path(), &MUSL))
        .status
        .success());
    let tools = temp.path().join("tools");
    link_tools(
        &tools,
        &[
            "sh",
            "uname",
            "grep",
            "head",
            "cut",
            "cp",
            "sha256sum",
            "mktemp",
            "mkdir",
            "chmod",
            "mv",
            "rm",
        ],
    );
    let installed = |dir: &str| temp.path().join(dir).join("bin/vorda");

    // Without minisign the SHA-256 check alone applies.
    let plain = run_installer(&release, &tools, &temp.path().join("plain"));
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert_eq!(fs::read(installed("plain")).unwrap(), ARTIFACT);
    assert!(!temp.path().join("plain/bin/vorda.minisig").exists());

    let calls = temp.path().join("minisign-calls");
    let stub = |code: i32| {
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit {code}\n",
            calls.display()
        );
        fs::write(tools.join("minisign"), script).unwrap();
        fs::set_permissions(tools.join("minisign"), fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(0);
    let unsigned = run_installer(&release, &tools, &temp.path().join("unsigned"));
    assert_eq!(unsigned.status.code(), Some(1));
    assert!(!installed("unsigned").exists());

    fs::write(release.join("SHA256SUMS.minisig"), b"signature").unwrap();
    // A signed manifest also needs the executable's own signature.
    let no_exe_sig = run_installer(&release, &tools, &temp.path().join("no-exe-sig"));
    assert_eq!(no_exe_sig.status.code(), Some(1));
    assert!(!installed("no-exe-sig").exists());

    for target in MUSL {
        let exe_sig = release.join(format!("vorda-0.2.0-{target}.minisig"));
        fs::write(exe_sig, b"exe signature").unwrap();
    }
    let signed = run_installer(&release, &tools, &temp.path().join("signed"));
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert_eq!(fs::read(installed("signed")).unwrap(), ARTIFACT);
    assert_eq!(
        fs::read(temp.path().join("signed/bin/vorda.minisig")).unwrap(),
        b"exe signature",
        "verify-self finds the signature beside the executable"
    );
    let args = fs::read_to_string(&calls).unwrap();
    let args: Vec<&str> = args.lines().collect();
    let after = |flag: &str| args[args.iter().position(|a| *a == flag).unwrap() + 1];
    let key = fs::read_to_string(repo().join("rust/release/vorda-release.pub")).unwrap();
    assert_eq!(
        after("-P"),
        key.lines().nth(1).unwrap(),
        "the committed release key"
    );
    assert!(after("-m").ends_with("SHA256SUMS"));
    assert!(after("-x").ends_with("SHA256SUMS.minisig"));

    stub(1);
    let bad = run_installer(&release, &tools, &temp.path().join("bad"));
    assert_eq!(bad.status.code(), Some(1));
    assert!(!installed("bad").exists());

    // A valid manifest signature does not excuse a bad executable signature.
    fs::write(
        tools.join("minisign"),
        "#!/bin/sh\ncase \"$*\" in *SHA256SUMS.minisig*) exit 0 ;; esac\nexit 1\n",
    )
    .unwrap();
    let bad_exe = run_installer(&release, &tools, &temp.path().join("bad-exe"));
    assert_eq!(bad_exe.status.code(), Some(1));
    assert!(!installed("bad-exe").exists());
}
