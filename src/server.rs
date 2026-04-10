use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::ServerFuture;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, UdpSocket};

use crate::config::DohConfig;
use crate::handler::AdlibitumHandler;

#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn load_cert_resolver(config: &DohConfig) -> anyhow::Result<Arc<dyn ResolvesServerCert>> {
    let cert_chain = CertificateDer::pem_file_iter(&config.cert_path)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;
    Ok(Arc::new(SingleCertResolver(Arc::new(certified_key))))
}

pub async fn run(
    handler: AdlibitumHandler,
    listen_addr: SocketAddr,
    doh_config: Option<DohConfig>,
) -> anyhow::Result<()> {
    let mut server = ServerFuture::new(handler);

    let udp_socket = UdpSocket::bind(listen_addr).await?;
    server.register_socket(udp_socket);

    let tcp_listener = TcpListener::bind(listen_addr).await?;
    server.register_listener(tcp_listener, Duration::from_secs(5));

    tracing::info!(%listen_addr, "DNS server listening (UDP/TCP)");

    if let Some(doh) = &doh_config {
        let cert_resolver = load_cert_resolver(doh)?;
        let https_listener = TcpListener::bind(doh.listen_addr).await?;
        server.register_https_listener(
            https_listener,
            Duration::from_secs(5),
            cert_resolver,
            doh.dns_hostname.clone(),
            doh.endpoint.clone(),
        )?;
        tracing::info!(listen_addr = %doh.listen_addr, endpoint = %doh.endpoint, "DoH server listening (HTTPS)");
    }

    server.block_until_done().await?;
    Ok(())
}
