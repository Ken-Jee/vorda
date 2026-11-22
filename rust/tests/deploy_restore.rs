//! Deployment contract exercised at the shell boundary without building a product.
#[cfg(unix)]
mod unix {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
    fn run(mode: &str, previous: bool) -> (i32, Option<Vec<u8>>, String) {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = tmp.path().join("installed prefix");
        fs::create_dir(&deploy).unwrap();
        if previous {
            fs::write(deploy.join("current"), b"accepted-old").unwrap();
        }
        let binary = tmp.path().join("new binary");
        fs::write(&binary, b"accepted-new").unwrap();
        let smoke = tmp.path().join("smoke");
        fs::write(&smoke, r#"#!/bin/sh
binary=$2
value=$(cat "$binary")
if [ "$value" = accepted-old ]; then
  case "$DEPLOY_TEST_MODE" in
    signal:*) kill -"${DEPLOY_TEST_MODE#signal:}" "$PPID" ;;
    old-fails) echo 'previous smoke rejected' >&2; exit 7 ;;
  esac
fi
if [ "$DEPLOY_TEST_MODE" = candidate-fails ] && [ "${binary##*/}" = candidate ]; then exit 8; fi
if [ "$DEPLOY_TEST_MODE" = installed-fails ] && [ "${binary##*/}" = current ] && [ "$value" = accepted-new ]; then exit 9; fi
"#).unwrap();
        fs::set_permissions(&smoke, fs::Permissions::from_mode(0o755)).unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("ci/deploy.sh");
        let output = Command::new("bash")
            .args([
                script.as_os_str(),
                deploy.as_os_str(),
                binary.as_os_str(),
                smoke.as_os_str(),
            ])
            .env("DEPLOY_TEST_MODE", mode)
            .output()
            .unwrap();
        let bytes = fs::read(deploy.join("current")).ok();
        (
            output.status.code().unwrap_or(-1),
            bytes,
            String::from_utf8(output.stderr).unwrap(),
        )
    }
    #[test]
    fn rejected_candidate_keeps_previous() {
        let (code, bytes, _) = run("candidate-fails", true);
        assert_ne!(code, 0);
        assert_eq!(bytes.as_deref(), Some(b"accepted-old".as_slice()));
    }
    #[test]
    fn rejected_install_restores_or_removes() {
        for previous in [true, false] {
            let (code, bytes, _) = run("installed-fails", previous);
            assert_ne!(code, 0);
            assert_eq!(
                bytes.as_deref(),
                previous.then_some(b"accepted-old".as_slice())
            );
        }
    }
    #[test]
    fn successful_install_with_and_without_previous() {
        for previous in [true, false] {
            let (code, bytes, _) = run("pass", previous);
            assert_eq!(code, 0);
            assert_eq!(bytes.as_deref(), Some(b"accepted-new".as_slice()));
        }
    }
    #[test]
    fn failed_previous_smoke_keeps_accepted_new_and_failure() {
        let (code, bytes, stderr) = run("old-fails", true);
        assert_eq!(code, 7);
        assert_eq!(bytes.as_deref(), Some(b"accepted-new".as_slice()));
        assert!(stderr.contains("previous smoke rejected"));
    }
    #[test]
    fn interrupted_rehearsal_keeps_accepted_new_and_failure() {
        for (sig, code) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
            let (actual, bytes, _) = run(&format!("signal:{sig}"), true);
            assert_eq!(actual, code, "{sig}");
            assert_eq!(bytes.as_deref(), Some(b"accepted-new".as_slice()));
        }
    }
}
