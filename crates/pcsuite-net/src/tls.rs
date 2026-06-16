//! A rustls TLS client that accepts the phone's self-signed certificate.
//!
//! The phone presents a self-signed cert on 10380/10381; the official client
//! never validates it. We replicate that with a `ServerCertVerifier` that
//! asserts every certificate is fine (it still performs the TLS handshake and
//! encrypts the channel — only the trust check is skipped).

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the shared no-verify client config (ALPN `http/1.1`).
fn client_config() -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("tls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn server_name_for(ip: &str) -> ServerName<'static> {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => ServerName::IpAddress(addr.into()),
        Err(_) => ServerName::try_from(ip.to_string())
            .unwrap_or_else(|_| ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into())),
    }
}

/// Connect TCP + TLS to `ip:port`, accepting the self-signed cert.
pub async fn connect_tls(ip: &str, port: u16) -> Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(Arc::new(client_config()?));
    let tcp = TcpStream::connect((ip, port))
        .await
        .with_context(|| format!("tcp connect {ip}:{port}"))?;
    tcp.set_nodelay(true).ok();
    let tls = connector
        .connect(server_name_for(ip), tcp)
        .await
        .context("tls handshake")?;
    Ok(tls)
}
