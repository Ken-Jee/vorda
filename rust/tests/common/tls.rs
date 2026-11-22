use std::{fs, path::Path, process::Command};

/// A fresh loopback identity whose validity does not depend on crossing a clock second.
pub fn certificate(cert: &Path, key: &Path) {
    let tmp = tempfile::tempdir().unwrap();
    let csr = tmp.path().join("request.pem");
    let config = tmp.path().join("ca.cnf");
    let index = tmp.path().join("index");
    let serial = tmp.path().join("serial");
    fs::write(&index, "").unwrap();
    fs::write(&serial, "01\n").unwrap();
    fs::write(
        &config,
        "[ca]\ndefault_ca=local\n[local]\ndatabase=$ENV::TEST_TLS_INDEX\nserial=$ENV::TEST_TLS_SERIAL\nnew_certs_dir=$ENV::TEST_TLS_DIR\ndefault_md=sha256\npolicy=subject\nx509_extensions=leaf\n[subject]\ncommonName=supplied\n[leaf]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n",
    )
    .unwrap();
    let request = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
        ])
        .arg(key)
        .arg("-out")
        .arg(&csr)
        .output()
        .expect("SETUP: openssl available");
    assert!(
        request.status.success(),
        "{}",
        String::from_utf8_lossy(&request.stderr)
    );
    // Fixed dates avoid wall-clock steps between OpenSSL and the TLS verifier. Each call still
    // uses a new key, so the wrong-CA tests exercise an independent, untrusted identity.
    let signed = Command::new("openssl")
        .args([
            "ca",
            "-selfsign",
            "-batch",
            "-notext",
            "-startdate",
            "20200101000000Z",
            "-enddate",
            "21200101000000Z",
            "-config",
        ])
        .arg(&config)
        .arg("-keyfile")
        .arg(key)
        .arg("-in")
        .arg(&csr)
        .arg("-out")
        .arg(cert)
        .env("TEST_TLS_INDEX", &index)
        .env("TEST_TLS_SERIAL", &serial)
        .env("TEST_TLS_DIR", tmp.path())
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
}
