mod config;
mod filter;
mod forwarder;
mod handler;
mod server;

use std::sync::Arc;

use config::Config;
use filter::Filter;
use forwarder::Forwarder;
use handler::IaretisHandler;

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
    let handler = IaretisHandler::new(filter, forwarder);

    // PID 1（distroless のコンテナ）では、ハンドラの無い合図は無視される。
    // SIGTERM（docker stop）と SIGINT を受けて、自分から止まる。
    let shutdown = shutdown_signal()?;
    server::run(handler, config.listen_addr, config.doh, shutdown).await
}

/// SIGTERM か SIGINT（Ctrl-C）で完了する Future を返す。
/// ハンドラはここで登録する（Future を待ち始める前に届いた合図も取りこぼさない）。
fn shutdown_signal() -> anyhow::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => tracing::info!("received SIGTERM"),
            _ = int.recv() => tracing::info!("received SIGINT"),
        }
    })
}
