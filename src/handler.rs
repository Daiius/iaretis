use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Header, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::filter::Filter;
use crate::forwarder::Forwarder;

fn serve_failed() -> ResponseInfo {
    let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
    metadata.response_code = ResponseCode::ServFail;
    let header = Header { metadata, counts: Default::default() };
    header.into()
}

/// これを超える転送クエリは warn に昇格させ、鈍い応答を埋もれさせない。
/// Cloudflare DoT の正常応答は概ね数十ms なので、200ms 超は上流の谷や
/// 特定 QTYPE の遅延を疑うライン。
const SLOW_QUERY_MS: u128 = 200;

/// SERVFAIL を返す上流失敗の原因種別。ログを grep 集計して
/// 「timeout が何件 / tls が何件」を把握し、DoT 安定化の進捗判断に使う。
/// 上流フォワーダは DoT なので Quinn/H3 系は発生せず、この分類で十分。
fn classify_cause(e: &NetError) -> &'static str {
    match e {
        NetError::Timeout => "timeout",
        NetError::RustlsError(_) => "tls",
        NetError::Io(_) | NetError::NoConnections | NetError::Busy => "connection",
        _ => "other",
    }
}

pub struct IaretisHandler {
    filter: Arc<Filter>,
    forwarder: Forwarder,
}

impl IaretisHandler {
    pub fn new(filter: Arc<Filter>, forwarder: Forwarder) -> Self {
        Self { filter, forwarder }
    }

    fn build_blocked_response(request: &Request, record_type: RecordType) -> Vec<Record> {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => return vec![],
        };
        let name = info.query.name().into();
        match record_type {
            RecordType::A => {
                vec![Record::from_rdata(name, 0, RData::A(A(Ipv4Addr::UNSPECIFIED)))]
            }
            RecordType::AAAA => {
                vec![Record::from_rdata(
                    name,
                    0,
                    RData::AAAA(AAAA(std::net::Ipv6Addr::UNSPECIFIED)),
                )]
            }
            _ => vec![],
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for IaretisHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start = Instant::now();
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => return serve_failed(),
        };

        let query_name = info.query.name().to_string();
        let record_type = info.query.query_type();

        // DNS の末尾ドットを除去して比較
        let domain = query_name.trim_end_matches('.');

        // クエリが到達したトランスポートとクライアント。iOS が DoH を無視して
        // 素の DNS にフォールバックすると、通常 proto=HTTPS(DoH) だった phone の
        // クエリが proto=UDP/TCP で現れる。フォールバック先が iaretis なら、
        // 「iOS が DoH を無視した」瞬間を無音ではなく信号として捉えられる。
        // 特に domain が DoH サーバ自身 (dns.faveo-systema.net) のクエリが
        // proto=UDP/TCP で来たら、iOS がブートストラップ解決を素の DNS で
        // 試みている＝DoH 接続確立前の状態を意味する。
        let proto = info.protocol;
        let src = info.src;

        if self.filter.is_blocked(domain) {
            let answers = Self::build_blocked_response(request, record_type);
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.response_code = ResponseCode::NoError;

            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.build(metadata, answers.iter(), &[], &[], &[]);

            match response_handle.send_response(response).await {
                Ok(resp_info) => {
                    tracing::info!(
                        path = "blocked",
                        proto = %proto,
                        src = %src,
                        qtype = %record_type,
                        domain,
                        rcode = "NoError",
                        latency_ms = start.elapsed().as_millis(),
                        "query"
                    );
                    resp_info
                }
                Err(e) => {
                    tracing::error!("failed to send blocked response: {e}");
                    serve_failed()
                }
            }
        } else {
            let name = info.query.name().into();
            match self.forwarder.resolve(&name, record_type).await {
                Ok(lookup) => {
                    let latency = start.elapsed().as_millis();
                    let records: Vec<&Record> = lookup.answers().iter().collect();
                    let mut metadata = Metadata::response_from_request(&request.metadata);
                    metadata.response_code = ResponseCode::NoError;

                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(metadata, records.iter().copied(), &[], &[], &[]);

                    match response_handle.send_response(response).await {
                        Ok(resp_info) => {
                            // 遅い応答（Chrome サジェスト等の「妙に鈍い」の正体）が
                            // 通常クエリに埋もれないよう、閾値超過は warn に昇格。
                            if latency > SLOW_QUERY_MS {
                                tracing::warn!(
                                    path = "forwarded",
                                    proto = %proto,
                                    src = %src,
                                    qtype = %record_type,
                                    domain,
                                    rcode = "NoError",
                                    latency_ms = latency,
                                    "slow query"
                                );
                            } else {
                                tracing::info!(
                                    path = "forwarded",
                                    proto = %proto,
                                    src = %src,
                                    qtype = %record_type,
                                    domain,
                                    rcode = "NoError",
                                    latency_ms = latency,
                                    "query"
                                );
                            }
                            resp_info
                        }
                        Err(e) => {
                            tracing::error!("failed to send forwarded response: {e}");
                            serve_failed()
                        }
                    }
                }
                Err(e) => {
                    let latency = start.elapsed().as_millis();
                    let response_code = match &e {
                        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                            // 上流が正常に返した負応答（NXDOMAIN/NODATA）。失敗ではない。
                            tracing::info!(
                                path = "forwarded",
                                proto = %proto,
                                src = %src,
                                qtype = %record_type,
                                domain,
                                rcode = %no_records.response_code,
                                latency_ms = latency,
                                "query (no records)"
                            );
                            no_records.response_code
                        }
                        _ => {
                            // 真の上流失敗。cause で timeout/tls/connection を切り分け、
                            // これが多発するなら DoT 安定化（本丸）が主因と判断できる。
                            tracing::warn!(
                                path = "forwarded",
                                proto = %proto,
                                src = %src,
                                qtype = %record_type,
                                domain,
                                rcode = "ServFail",
                                cause = classify_cause(&e),
                                latency_ms = latency,
                                error = %e,
                                "upstream failure"
                            );
                            ResponseCode::ServFail
                        }
                    };
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.error_msg(&request.metadata, response_code);
                    match response_handle.send_response(response).await {
                        Ok(info) => info,
                        Err(_) => serve_failed(),
                    }
                }
            }
        }
    }
}
