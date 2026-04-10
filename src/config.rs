use std::net::SocketAddr;
use std::path::PathBuf;

pub struct Config {
    pub listen_addr: SocketAddr,
    pub filter_file: Option<PathBuf>,
    pub doh: Option<DohConfig>,
}

pub struct DohConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub endpoint: String,
}

impl Config {
    pub fn load() -> Self {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:5300".into())
            .parse()
            .expect("invalid LISTEN_ADDR");

        let filter_file = std::env::var("FILTER_FILE").ok().map(PathBuf::from);

        let doh_addr = std::env::var("DOH_LISTEN_ADDR");
        let doh_cert = std::env::var("DOH_CERT_PATH");
        let doh_key = std::env::var("DOH_KEY_PATH");

        let doh = match (&doh_addr, &doh_cert, &doh_key) {
            (Ok(addr), Ok(cert), Ok(key)) => {
                let endpoint = match std::env::var("DOH_SECRET_TOKEN") {
                    Ok(token) if !token.is_empty() => format!("/dns-query/{token}"),
                    _ => {
                        tracing::warn!("DOH_SECRET_TOKEN is not set, DoH endpoint has no authentication");
                        "/dns-query".to_string()
                    }
                };
                Some(DohConfig {
                    listen_addr: addr.parse().expect("invalid DOH_LISTEN_ADDR"),
                    cert_path: PathBuf::from(cert),
                    key_path: PathBuf::from(key),
                    endpoint,
                })
            }
            (Err(_), Err(_), Err(_)) => {
                tracing::info!("DoH disabled (DOH_LISTEN_ADDR, DOH_CERT_PATH, DOH_KEY_PATH not set)");
                None
            }
            _ => {
                tracing::warn!(
                    DOH_LISTEN_ADDR = doh_addr.is_ok(),
                    DOH_CERT_PATH = doh_cert.is_ok(),
                    DOH_KEY_PATH = doh_key.is_ok(),
                    "DoH disabled: DOH_LISTEN_ADDR, DOH_CERT_PATH, DOH_KEY_PATH must all be set"
                );
                None
            }
        };

        Self {
            listen_addr,
            filter_file,
            doh,
        }
    }
}
