use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use h2::server;
use http::{Method, Response, StatusCode, header};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

/// DoH (DNS-over-HTTPS) サーバー
/// GET/POST の両方に対応し、内部の DNS サーバーに UDP でプロキシする
pub async fn run(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    endpoint: Arc<str>,
    dns_addr: SocketAddr,
) {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("DoH accept error: {e}");
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let endpoint = endpoint.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("DoH TLS handshake failed from {peer_addr}: {e}");
                    return;
                }
            };

            let mut h2_conn = match server::handshake(tls_stream).await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!("DoH h2 handshake failed from {peer_addr}: {e}");
                    return;
                }
            };

            while let Some(result) = h2_conn.accept().await {
                let (request, mut respond) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("DoH h2 accept error from {peer_addr}: {e}");
                        return;
                    }
                };

                let endpoint = endpoint.clone();
                tokio::spawn(async move {
                    let response = handle_request(request, &endpoint, dns_addr).await;
                    if let Err(e) = send_response(&mut respond, response).await {
                        tracing::debug!("DoH response send error: {e}");
                    }
                });
            }
        });
    }
}

struct DohResponse {
    status: StatusCode,
    body: Bytes,
}

async fn handle_request(
    request: http::Request<h2::RecvStream>,
    endpoint: &str,
    dns_addr: SocketAddr,
) -> DohResponse {
    // パスの検証
    let path = request.uri().path();
    if path != endpoint {
        tracing::debug!(path, "DoH bad path");
        return DohResponse {
            status: StatusCode::NOT_FOUND,
            body: Bytes::new(),
        };
    }

    // DNS クエリの抽出（GET: クエリパラメータ, POST: ボディ）
    let dns_query = match *request.method() {
        Method::GET => extract_from_query_param(request.uri()),
        Method::POST => extract_from_body(request.into_body()).await,
        _ => {
            return DohResponse {
                status: StatusCode::METHOD_NOT_ALLOWED,
                body: Bytes::new(),
            };
        }
    };

    let dns_query = match dns_query {
        Ok(q) => q,
        Err(e) => {
            tracing::debug!("DoH bad request: {e}");
            return DohResponse {
                status: StatusCode::BAD_REQUEST,
                body: Bytes::new(),
            };
        }
    };

    // 内部 DNS サーバーに UDP でプロキシ
    match dns_udp_proxy(&dns_query, dns_addr).await {
        Ok(response) => DohResponse {
            status: StatusCode::OK,
            body: Bytes::from(response),
        },
        Err(e) => {
            tracing::warn!("DoH upstream DNS error: {e}");
            DohResponse {
                status: StatusCode::BAD_GATEWAY,
                body: Bytes::new(),
            }
        }
    }
}

fn extract_from_query_param(uri: &http::Uri) -> Result<Vec<u8>, String> {
    let query = uri.query().ok_or("missing query string")?;
    let dns_param = query
        .split('&')
        .find_map(|param| param.strip_prefix("dns="))
        .ok_or("missing dns parameter")?;
    URL_SAFE_NO_PAD
        .decode(dns_param)
        .map_err(|e| format!("base64 decode error: {e}"))
}

async fn extract_from_body(mut body: h2::RecvStream) -> Result<Vec<u8>, String> {
    const MAX_DNS_MESSAGE_SIZE: usize = 8192;
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| format!("body read error: {e}"))?;
        data.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|e| format!("flow control error: {e}"))?;
        if data.len() > MAX_DNS_MESSAGE_SIZE {
            return Err(format!("body too large (>{MAX_DNS_MESSAGE_SIZE} bytes)"));
        }
    }
    Ok(data)
}

async fn dns_udp_proxy(query: &[u8], dns_addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(query, dns_addr).await?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS query timed out"))??;
    buf.truncate(len);
    Ok(buf)
}

async fn send_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    doh_response: DohResponse,
) -> Result<(), h2::Error> {
    let mut builder = Response::builder().status(doh_response.status);
    if doh_response.status == StatusCode::OK {
        builder = builder
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::CONTENT_LENGTH, doh_response.body.len());
    }
    let response = builder.body(()).unwrap();

    let mut send_stream = respond.send_response(response, doh_response.body.is_empty())?;
    if !doh_response.body.is_empty() {
        send_stream.send_data(doh_response.body, true)?;
    }
    Ok(())
}
