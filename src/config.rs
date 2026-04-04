use std::net::SocketAddr;
use std::path::PathBuf;

pub struct Config {
    pub listen_addr: SocketAddr,
    pub filter_file: Option<PathBuf>,
}

impl Config {
    pub fn load() -> Self {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:5300".into())
            .parse()
            .expect("invalid LISTEN_ADDR");

        let filter_file = std::env::var("FILTER_FILE").ok().map(PathBuf::from);

        Self {
            listen_addr,
            filter_file,
        }
    }
}
