//! Built-in TLS for the web UI and the agent ingest port.
//!
//! The operator supplies a certificate chain and private key in PEM form
//! (`--tls-cert`, `--tls-key`); DENIS never generates or trusts certificates on
//! its own. rustls with the `ring` provider does the protocol work (TLS 1.2 and
//! 1.3 only, modern cipher suites by rustls's defaults, no legacy protocols).
//!
//! Certificates are re-read every few hours, so a renewed certificate (Let's
//! Encrypt, an internal CA) takes effect without a restart; a failed reload keeps
//! the old certificate and logs a warning.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

const RELOAD_EVERY: Duration = Duration::from_secs(6 * 3600);

/// Make `ring` the process-wide crypto provider (idempotent).
fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Read and validate the certificate and key. Fails with a message that names the file.
pub async fn load(cert: &Path, key: &Path) -> Result<RustlsConfig> {
    install_provider();
    RustlsConfig::from_pem_file(cert, key)
        .await
        .with_context(|| format!("loading the TLS certificate {} and key {} (both must be PEM files, the key unencrypted)", cert.display(), key.display()))
}

/// Keep the certificate fresh for as long as the returned task runs.
pub fn spawn_reloader(cfg: RustlsConfig, cert: PathBuf, key: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RELOAD_EVERY).await;
            match cfg.reload_from_pem_file(&cert, &key).await {
                Ok(()) => tracing::info!("reloaded the TLS certificate"),
                Err(e) => tracing::warn!("could not reload the TLS certificate (keeping the old one): {e:#}"),
            }
        }
    })
}

/// The running console's certificate: the live config (so it can be swapped without a restart) and,
/// when DENIS manages the certificate, its folder.
pub struct TlsHandle {
    pub config: RustlsConfig,
    /// `Some` = DENIS-managed (generated or uploaded); `None` = files given on the command line.
    pub dir: Option<PathBuf>,
    pub names: Vec<String>,
}

/// Keep a DENIS-managed certificate fresh: renew it when it nears its end or the machine gets a
/// new address, and pick up the new files.
pub fn spawn_managed_reloader(h: std::sync::Arc<TlsHandle>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(dir) = h.dir.clone() else { return };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let (d, n) = (dir.clone(), h.names.clone());
            match tokio::task::spawn_blocking(move || crate::certs::ensure(&d, &n, crate::model::now_ts())).await {
                Ok(Ok(true)) => match h.config.reload_from_pem_file(dir.join(crate::certs::SERVER_CERT), dir.join(crate::certs::SERVER_KEY)).await {
                    Ok(()) => tracing::info!("renewed the console's TLS certificate"),
                    Err(e) => tracing::warn!("renewed certificate could not be loaded: {e:#}"),
                },
                Ok(Err(e)) => tracing::warn!("could not check the TLS certificate: {e:#}"),
                _ => {}
            }
        }
    })
}

/// Serve `app` over TLS on an already-bound listener.
pub async fn serve(listener: tokio::net::TcpListener, app: Router, cfg: RustlsConfig) -> std::io::Result<()> {
    let std_listener = listener.into_std()?;
    axum_server::from_tcp_rustls(std_listener, cfg)?
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Start a tiny HTTPS server on the generated certificate; returns its port and handle.
    async fn serve_generated(dir: &std::path::Path) -> (u16, Arc<TlsHandle>) {
        crate::certs::ensure(dir, &[], crate::model::now_ts()).unwrap();
        let config = load(&dir.join(crate::certs::SERVER_CERT), &dir.join(crate::certs::SERVER_KEY)).await.unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let app = Router::new().route("/api/health", axum::routing::get(|| async { "ok" }));
        tokio::spawn(serve(l, app, config.clone()));
        (port, Arc::new(TlsHandle { config, dir: Some(dir.to_path_buf()), names: Vec::new() }))
    }

    #[tokio::test]
    async fn the_generated_certificate_is_accepted_by_a_client_that_trusts_the_local_ca_and_refused_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let (port, _h) = serve_generated(dir.path()).await;
        let url = format!("https://localhost:{port}/api/health");
        let ca = dir.path().join(crate::certs::CA_CERT);
        // a client pinned to the CA (an agent with --master-ca) connects, by name and by address
        let ok = tokio::task::spawn_blocking({
            let (ca, url) = (ca.clone(), url.clone());
            move || {
                let c = crate::agent::http_client(Some(&ca)).unwrap();
                (c.get(&url).call().map(|r| r.status().as_u16()).map_err(|e| e.to_string()), c.get(url.replace("localhost", "127.0.0.1")).call().map(|r| r.status().as_u16()).map_err(|e| e.to_string()))
            }
        })
        .await
        .unwrap();
        assert_eq!(ok, (Ok(200), Ok(200)));
        // a client that trusts only the public web roots refuses it: nobody but the holder of the CA is trusted
        let refused = tokio::task::spawn_blocking(move || crate::agent::http_client(None).unwrap().get(&url).call().is_err()).await.unwrap();
        assert!(refused);
    }

    #[tokio::test]
    async fn a_certificate_uploaded_while_running_is_served_from_the_next_connection_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (port, h) = serve_generated(dir.path()).await;
        let before = crate::certs::info(dir.path()).unwrap().fingerprint;
        // somebody else's certificate for localhost
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        p.is_ca = rcgen::IsCa::ExplicitNoCa;
        let cert = p.self_signed(&key).unwrap();
        let now = crate::model::now_ts();
        let info = crate::certs::install_custom(dir.path(), &cert.pem(), &key.serialize_pem(), now).unwrap();
        h.config.reload_from_pem_file(dir.path().join(crate::certs::SERVER_CERT), dir.path().join(crate::certs::SERVER_KEY)).await.unwrap();
        assert_ne!(info.fingerprint, before);
        // a client that trusts exactly that certificate now connects; the old CA-only client does not
        let (custom_ca, url) = (dir.path().join("custom-root.pem"), format!("https://localhost:{port}/api/health"));
        std::fs::write(&custom_ca, cert.pem()).unwrap();
        let (u1, u2) = (url.clone(), url.clone());
        let new_ok = tokio::task::spawn_blocking(move || crate::agent::http_client(Some(&custom_ca)).unwrap().get(&u1).call().map(|r| r.status().as_u16()).map_err(|e| e.to_string())).await.unwrap();
        let ca = dir.path().join(crate::certs::CA_CERT);
        let old_refused = tokio::task::spawn_blocking(move || crate::agent::http_client(Some(&ca)).unwrap().get(&u2).call().is_err()).await.unwrap();
        assert_eq!(new_ok, Ok(200), "the uploaded certificate is live");
        assert!(old_refused, "the generated one is no longer served");
    }

    #[tokio::test]
    async fn bad_or_missing_certificate_files_are_refused_with_a_message_naming_them() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let e = format!("{:#}", load(&c, &k).await.err().unwrap());
        assert!(e.contains("c.pem") && e.contains("k.pem"), "{e}");
        std::fs::write(&c, "not a certificate").unwrap();
        std::fs::write(&k, "not a key").unwrap();
        assert!(load(&c, &k).await.is_err());
    }
}
