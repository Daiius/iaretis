use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use crate::config::DohConfig;
use crate::handler::IaretisHandler;

fn build_tls_acceptor(config: &DohConfig) -> anyhow::Result<TlsAcceptor> {
    let cert_chain = CertificateDer::pem_file_iter(&config.cert_path)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;

    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertResolver(Arc::new(certified_key))));
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

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
    server.register_listener(tcp_listener, Duration::from_secs(5));

    tracing::info!(%listen_addr, "DNS server listening (UDP/TCP)");

    if let Some(doh) = &doh_config {
        let tls_acceptor = build_tls_acceptor(doh)?;
        let https_listener = TcpListener::bind(doh.listen_addr).await?;
        let endpoint: Arc<str> = Arc::from(doh.endpoint.as_str());

        tracing::info!(
            listen_addr = %doh.listen_addr,
            endpoint = %doh.endpoint,
            "DoH server listening (HTTPS)"
        );

        // DoH サーバーを別タスクで起動（DNS サーバーに UDP でプロキシ）
        // listen_addr が 0.0.0.0 の場合は 127.0.0.1 に変換
        let dns_proxy_addr = SocketAddr::new(
            match listen_addr.ip() {
                std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                ip => ip,
            },
            listen_addr.port(),
        );
        tokio::spawn(crate::doh::run(
            https_listener,
            tls_acceptor,
            endpoint,
            dns_proxy_addr,
        ));
    }

    server.block_until_done().await?;
    Ok(())
}
