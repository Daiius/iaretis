use std::future::Future;
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

/// 停止の合図を受けてから、終わるのを待つ上限。
/// docker stop の猶予（既定 10 秒）を過ぎると SIGKILL されるので、それより十分短くする。
/// DNS のやり取りは 1 回が一瞬で、待つべき長い処理も無いので、5 秒で足りる。
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// サーバーを起こし、`shutdown` が完了するまで動かす。
///
/// `shutdown` が完了したら、hickory の `shutdown_gracefully()` で止める。
/// 各待ち受け（UDP・TCP・DoH）は新しい受け付けをやめてすぐに抜け、そのとき処理中の
/// 接続・問い合わせのタスクは（hickory の内部の JoinSet ごと）打ち切られる。待つのは
/// 待ち受けのタスクが抜けるところまでで、`SHUTDOWN_TIMEOUT` を過ぎたら待つのをやめて返る。
pub async fn run(
    handler: IaretisHandler,
    listen_addr: SocketAddr,
    doh_config: Option<DohConfig>,
    shutdown: impl Future<Output = ()>,
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

    tokio::select! {
        // 合図の前にサーバーが終わった（待ち受けの異常など）。これまでどおりエラーを返す。
        result = server.block_until_done() => {
            result?;
            return Ok(());
        }
        () = shutdown => {}
    }

    tracing::info!("shutdown signal received, stopping");
    match tokio::time::timeout(SHUTDOWN_TIMEOUT, server.shutdown_gracefully()).await {
        Ok(Ok(())) => tracing::info!("server stopped"),
        Ok(Err(error)) => tracing::warn!(%error, "error while stopping server"),
        Err(_) => tracing::warn!(?SHUTDOWN_TIMEOUT, "server did not stop in time, exiting anyway"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;
    use crate::forwarder::Forwarder;
    use tokio::sync::oneshot;

    fn test_handler() -> IaretisHandler {
        IaretisHandler::new(Arc::new(Filter::new([])), Forwarder::new())
    }

    /// 空いているポートを 1 つ取る（UDP と TCP の両方で使う）。
    fn free_addr() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    #[tokio::test]
    async fn returns_when_shutdown_future_completes() {
        let addr = free_addr();
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(run(test_handler(), addr, None, async {
            let _ = rx.await;
        }));

        // 待ち受けが始まるまで待つ（TCP に繋がれば始まっている）。
        let mut connected = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(connected, "server did not start listening");

        tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("run did not return after shutdown")
            .unwrap();
        assert!(result.is_ok());

        // 待ち受けを閉じている（同じアドレスにもう一度 bind できる）。
        std::net::TcpListener::bind(addr).unwrap();
    }

    #[tokio::test]
    async fn open_tcp_connection_does_not_block_shutdown() {
        let addr = free_addr();
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(run(test_handler(), addr, None, async {
            let _ = rx.await;
        }));

        let mut conn = None;
        for _ in 0..50 {
            if let Ok(c) = tokio::net::TcpStream::connect(addr).await {
                conn = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // 問い合わせを送らずに繋いだままにする（接続のタイムアウト 5 秒より短い時間で止める）。
        let _conn = conn.expect("server did not start listening");

        tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("run waited for the open TCP connection")
            .unwrap();
        assert!(result.is_ok());
    }
}
