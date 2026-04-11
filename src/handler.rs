use std::net::Ipv4Addr;
use std::sync::Arc;

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
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => return serve_failed(),
        };

        let query_name = info.query.name().to_string();
        let record_type = info.query.query_type();

        // DNS の末尾ドットを除去して比較
        let domain = query_name.trim_end_matches('.');

        if self.filter.is_blocked(domain) {
            tracing::info!(domain, "blocked");
            let answers = Self::build_blocked_response(request, record_type);
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.response_code = ResponseCode::NoError;

            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.build(metadata, answers.iter(), &[], &[], &[]);

            match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    tracing::error!("failed to send blocked response: {e}");
                    serve_failed()
                }
            }
        } else {
            tracing::debug!(domain, "forwarding");
            let name = info.query.name().into();
            match self.forwarder.resolve(&name, record_type).await {
                Ok(lookup) => {
                    let records: Vec<&Record> = lookup.answers().iter().collect();
                    let mut metadata = Metadata::response_from_request(&request.metadata);
                    metadata.response_code = ResponseCode::NoError;

                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.build(metadata, records.iter().copied(), &[], &[], &[]);

                    match response_handle.send_response(response).await {
                        Ok(info) => info,
                        Err(e) => {
                            tracing::error!("failed to send forwarded response: {e}");
                            serve_failed()
                        }
                    }
                }
                Err(e) => {
                    let response_code = match &e {
                        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                            tracing::debug!(domain, response_code = %no_records.response_code, "no records found");
                            no_records.response_code
                        }
                        _ => {
                            tracing::warn!(domain, "upstream resolve failed: {e}");
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
