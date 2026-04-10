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
    pub dns_hostname: Option<String>,
    pub endpoint: String,
}

impl Config {
    pub fn load() -> Self {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:5300".into())
            .parse()
            .expect("invalid LISTEN_ADDR");

        let filter_file = std::env::var("FILTER_FILE").ok().map(PathBuf::from);

        let doh = match (
            std::env::var("DOH_LISTEN_ADDR"),
            std::env::var("DOH_CERT_PATH"),
            std::env::var("DOH_KEY_PATH"),
        ) {
            (Ok(addr), Ok(cert), Ok(key)) => {
                let endpoint = match std::env::var("DOH_SECRET_TOKEN") {
                    Ok(token) => format!("/dns-query/{token}"),
                    Err(_) => "/dns-query".to_string(),
                };
                Some(DohConfig {
                    listen_addr: addr.parse().expect("invalid DOH_LISTEN_ADDR"),
                    cert_path: PathBuf::from(cert),
                    key_path: PathBuf::from(key),
                    dns_hostname: std::env::var("DOH_HOSTNAME").ok(),
                    endpoint,
                })
            }
            _ => None,
        };

        Self {
            listen_addr,
            filter_file,
            doh,
        }
    }
}
