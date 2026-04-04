mod config;
mod filter;
mod forwarder;
mod handler;
mod server;

use std::sync::Arc;

use config::Config;
use filter::Filter;
use forwarder::Forwarder;
use handler::AdlibitumHandler;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iaretis=info".parse().unwrap()),
        )
        .init();

    let config = Config::load();

    let filter = match &config.filter_file {
        Some(path) => {
            tracing::info!(?path, "loading filter from file");
            Filter::from_file(path)?
        }
        None => {
            tracing::info!("no FILTER_FILE set, using built-in test blocklist");
            Filter::new([
                "ads.example.com".into(),
                "tracking.example.com".into(),
                "doubleclick.net".into(),
            ])
        }
    };
    tracing::info!(entries = filter.len(), "filter loaded");

    let filter = Arc::new(filter);
    let forwarder = Forwarder::new();
    let handler = AdlibitumHandler::new(filter, forwarder);

    server::run(handler, config.listen_addr).await
}
