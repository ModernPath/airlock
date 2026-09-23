//! End-to-end tests for proxy tools, through a real daemon and a real curl.
//!
//! These stop short of a completed request: the proxy resolves the upstream
//! itself and refuses any address that is not globally routable, so a local
//! test server cannot stand in as the upstream without a production knob that
//! turns the SSRF filter off — which is exactly the knob that must not exist.
//! The completed-request path is covered instead in `src/proxy/server.rs`,
//! where a `cfg(test)` connector can point a route at a local rustls server
//! and drive the whole thing with the system curl.
//!
//! What is checked here is everything the daemon owns: the CA file's
//! lifecycle, that the tool is pointed at the proxy and refused for an
//! unrouted host, and that the sandbox — not just the environment — is what
//! stops a tool that tries to go around the proxy.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod e2e_helpers;

use std::path::Path;

use e2e_helpers::*;

/// A config declaring curl as a proxy tool with one route.
fn proxy_config() -> String {
    config_with_tools(
        r#"
[secrets.TEST_E2E_SECRET]
source = "env"

[tools.curl]
description = "HTTP client for the example API"
proxy = true

[[tools.curl.routes]]
host   = "api.example.com"
inject = { header = "X-Test-Secret", value = "tok-{secret}", secret = "TEST_E2E_SECRET" }
allow  = ["GET /**"]
"#,
    )
}

fn curl_available() -> bool {
    Path::new("/usr/bin/curl").exists()
}

#[test]
fn daemon_publishes_and_removes_the_ca_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &proxy_config());
    let _guard = EnvGuard::new(&[
        ("HOME", tmp.path().to_str().unwrap()),
        ("TEST_E2E_SECRET", "e2e-secret-value"),
    ]);

    let daemon = start_daemon(tmp.path());
    let ca_path = tmp.path().join("airlock-ca.pem");

    let pem = std::fs::read_to_string(&ca_path)
        .expect("a daemon with a proxy tool must publish its CA certificate");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(
        !pem.contains("PRIVATE KEY"),
        "only the certificate may reach disk"
    );

    daemon.shutdown();
    assert!(
        !ca_path.exists(),
        "the CA certificate must be removed at shutdown"
    );
}

#[test]
fn a_daemon_without_proxy_tools_publishes_no_ca() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());
    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    let daemon = start_daemon(tmp.path());
    assert!(!tmp.path().join("airlock-ca.pem").exists());
    daemon.shutdown();
}

#[test]
fn a_stale_ca_certificate_is_cleaned_up_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &config_with_sh_no_secrets());
    let _guard = EnvGuard::new(&[("HOME", tmp.path().to_str().unwrap())]);

    // What a crashed daemon would leave behind.
    let ca_path = tmp.path().join("airlock-ca.pem");
    std::fs::write(&ca_path, "stale").unwrap();
    std::fs::write(tmp.path().join("airlock.pid"), "999999").unwrap();

    let daemon = start_daemon(tmp.path());
    assert!(
        !ca_path.exists(),
        "a leftover CA certificate must not survive the stale-state sweep"
    );
    daemon.shutdown();
}

#[test]
fn an_unrouted_host_is_refused_by_the_proxy() {
    if !curl_available() {
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &proxy_config());
    let _guard = EnvGuard::new(&[
        ("HOME", tmp.path().to_str().unwrap()),
        ("TEST_E2E_SECRET", "e2e-secret-value"),
    ]);
    let daemon = start_daemon(tmp.path());
    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // No route covers this host, so the proxy answers the CONNECT with 403 and
    // never resolves or dials anything — the check is hermetic.
    let result = exec_tool(
        &daemon.socket_path,
        "curl",
        &["-sS", "--max-time", "20", "https://unrouted.example.org/"],
        cwd.to_str().unwrap(),
    );

    assert_ne!(
        result.exit_code,
        Some(0),
        "an unrouted host must not succeed; stderr: {}",
        result.stderr
    );
    assert!(
        result.stderr.contains("403"),
        "curl should report the proxy's refusal; stderr: {}",
        result.stderr
    );

    daemon.shutdown();
}

#[test]
fn going_around_the_proxy_is_stopped_by_the_sandbox() {
    if !curl_available() {
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &proxy_config());
    let _guard = EnvGuard::new(&[
        ("HOME", tmp.path().to_str().unwrap()),
        ("TEST_E2E_SECRET", "e2e-secret-value"),
    ]);
    let daemon = start_daemon(tmp.path());
    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // `--noproxy '*'` discards the environment the daemon set, which is the
    // point: the environment is guidance, the sandbox is enforcement. The
    // profile permits no DNS and no destination but the proxy port, so this
    // fails without a packet leaving the machine.
    let result = exec_tool(
        &daemon.socket_path,
        "curl",
        &[
            "-sS",
            "--max-time",
            "20",
            "--noproxy",
            "*",
            "https://api.example.com/",
        ],
        cwd.to_str().unwrap(),
    );

    assert_ne!(
        result.exit_code,
        Some(0),
        "a direct connection must fail; stderr: {}",
        result.stderr
    );
    assert!(
        result.stderr.contains("Could not resolve host")
            || result.stderr.contains("Couldn't connect")
            || result.stderr.contains("Failed to connect"),
        "the failure should come from the sandbox, not from the proxy; stderr: {}",
        result.stderr
    );

    daemon.shutdown();
}

#[test]
fn a_direct_tcp_connect_is_denied_not_timed_out() {
    if !curl_available() {
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    write_config(tmp.path(), &proxy_config());
    let _guard = EnvGuard::new(&[
        ("HOME", tmp.path().to_str().unwrap()),
        ("TEST_E2E_SECRET", "e2e-secret-value"),
    ]);
    let daemon = start_daemon(tmp.path());
    let cwd = std::fs::canonicalize(tmp.path()).unwrap();

    // An IP literal takes DNS out of the picture, which matters on Linux:
    // Landlock does not cover UDP, so a name lookup there proves nothing about
    // the TCP rule. 192.0.2.1 (TEST-NET-1) is unroutable, so without the
    // sandbox this connect would hang until `--max-time` and exit 28. A
    // sandbox denial fails the connect() itself: exit 7, immediately.
    let result = exec_tool(
        &daemon.socket_path,
        "curl",
        &[
            "-sS",
            "--max-time",
            "10",
            "--noproxy",
            "*",
            "https://192.0.2.1/",
        ],
        cwd.to_str().unwrap(),
    );

    assert_eq!(
        result.exit_code,
        Some(7),
        "connect() must be refused by the sandbox, not time out; stderr: {}",
        result.stderr
    );

    daemon.shutdown();
}
