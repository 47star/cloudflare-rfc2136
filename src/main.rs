mod cloudflare;
mod config;
mod dns;
mod error;

use cloudflare::CloudflareClient;
use config::AppConfig;
use error::Result;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        error!(%error, "service exited");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;
    init_tracing(&config.log_level)?;

    let cloudflare = CloudflareClient::new(
        config.cloudflare_zone_id.clone(),
        config.cloudflare_api_token.clone(),
    )?;

    info!(
        udp = %config.listen_udp,
        tcp = %config.listen_tcp,
        zone = %config.dns_zone,
        suffix = %config.allowed_record_suffix,
        ttl = config.default_ttl,
        "starting RFC2136 bridge"
    );

    dns::run(config, cloudflare).await
}

fn init_tracing(log_level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(log_level)
        .map_err(|error| error::Error::Config(format!("invalid LOG_LEVEL: {error}")))?;

    fmt()
        .with_env_filter(filter)
        .json()
        .try_init()
        .map_err(|error| error::Error::Config(format!("failed to initialize logging: {error}")))?;

    Ok(())
}
