use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};

use crate::handler::AdlibitumHandler;

pub async fn run(handler: AdlibitumHandler, listen_addr: SocketAddr) -> anyhow::Result<()> {
    let mut server = ServerFuture::new(handler);

    let udp_socket = UdpSocket::bind(listen_addr).await?;
    server.register_socket(udp_socket);

    let tcp_listener = TcpListener::bind(listen_addr).await?;
    server.register_listener(tcp_listener, Duration::from_secs(5));

    tracing::info!(%listen_addr, "DNS server listening");
    server.block_until_done().await?;
    Ok(())
}
