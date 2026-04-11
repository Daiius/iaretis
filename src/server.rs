use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, UdpSocket};

use crate::config::DohConfig;
use crate::handler::IaretisHandler;

#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub async fn run(
    handler: IaretisHandler,
    listen_addr: SocketAddr,
    doh_config: Option<DohConfig>,
) -> anyhow::Result<()> {
    let mut server = Server::new(handler);

    let udp_socket = UdpSocket::bind(listen_addr).await?;
    server.register_socket(udp_socket);

    let tcp_listener = TcpListener::bind(listen_addr).await?;
    server.register_listener(tcp_listener, Duration::from_secs(5), 1024);

    tracing::info!(%listen_addr, "DNS server listening (UDP/TCP)");

    if let Some(doh) = &doh_config {
        let cert_chain = CertificateDer::pem_file_iter(&doh.cert_path)?
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&doh.key_path)?;
        let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;
        let cert_resolver: Arc<dyn rustls::server::ResolvesServerCert> =
            Arc::new(SingleCertResolver(Arc::new(certified_key)));

        let https_listener = TcpListener::bind(doh.listen_addr).await?;

        tracing::info!(
            listen_addr = %doh.listen_addr,
            endpoint = %doh.endpoint,
            "DoH server listening (HTTPS)"
        );

        server.register_https_listener(
            https_listener,
            Duration::from_secs(5),
            cert_resolver,
            None,
            doh.endpoint.clone(),
        )?;
    }

    server.block_until_done().await?;
    Ok(())
}
