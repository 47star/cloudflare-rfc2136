use std::net::SocketAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hickory_proto::rr::Name;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct AppConfig {
    pub listen_udp: SocketAddr,
    pub listen_tcp: SocketAddr,
    pub dns_zone: Name,
    pub allowed_record_suffix: Name,
    pub cloudflare_zone_id: String,
    pub cloudflare_api_token: String,
    pub default_ttl: u32,
    pub tsig_key_name: Name,
    pub tsig_secret: Vec<u8>,
    pub tsig_algorithm: TsigAlgorithm,
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    listen_udp: String,
    listen_tcp: String,
    dns_zone: String,
    allowed_record_suffix: String,
    cloudflare_zone_id: String,
    cloudflare_api_token: String,
    default_ttl: String,
    tsig_key_name: String,
    tsig_secret: String,
    tsig_algorithm: String,
    log_level: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let raw: RawConfig = envy::from_env()
            .map_err(|error| Error::Config(format!("missing or invalid environment: {error}")))?;

        let listen_udp = parse_socket_addr("LISTEN_UDP", &raw.listen_udp)?;
        let listen_tcp = parse_socket_addr("LISTEN_TCP", &raw.listen_tcp)?;
        let dns_zone = parse_name("DNS_ZONE", &raw.dns_zone)?;
        let allowed_record_suffix =
            parse_name("ALLOWED_RECORD_SUFFIX", &raw.allowed_record_suffix)?;

        if !dns_zone.zone_of(&allowed_record_suffix) {
            return Err(Error::Config(
                "ALLOWED_RECORD_SUFFIX must be equal to DNS_ZONE or below it".to_string(),
            ));
        }

        if raw.cloudflare_zone_id.trim().is_empty() {
            return Err(Error::Config(
                "CLOUDFLARE_ZONE_ID must not be empty".to_string(),
            ));
        }

        if raw.cloudflare_api_token.trim().is_empty() {
            return Err(Error::Config(
                "CLOUDFLARE_API_TOKEN must not be empty".to_string(),
            ));
        }

        let default_ttl = raw.default_ttl.parse::<u32>().map_err(|error| {
            Error::Config(format!("DEFAULT_TTL must be an unsigned integer: {error}"))
        })?;

        if default_ttl == 0 {
            return Err(Error::Config(
                "DEFAULT_TTL must be greater than 0".to_string(),
            ));
        }

        let tsig_key_name = parse_name("TSIG_KEY_NAME", &raw.tsig_key_name)?;
        let tsig_secret = STANDARD.decode(raw.tsig_secret.trim()).map_err(|error| {
            Error::Config(format!("TSIG_SECRET must be base64 encoded: {error}"))
        })?;

        if tsig_secret.is_empty() {
            return Err(Error::Config(
                "TSIG_SECRET must decode to at least one byte".to_string(),
            ));
        }

        let tsig_algorithm = parse_tsig_algorithm(&raw.tsig_algorithm)?;

        EnvFilter::try_new(raw.log_level.as_str())
            .map_err(|error| Error::Config(format!("LOG_LEVEL is invalid: {error}")))?;

        Ok(Self {
            listen_udp,
            listen_tcp,
            dns_zone,
            allowed_record_suffix,
            cloudflare_zone_id: raw.cloudflare_zone_id,
            cloudflare_api_token: raw.cloudflare_api_token,
            default_ttl,
            tsig_key_name,
            tsig_secret,
            tsig_algorithm,
            log_level: raw.log_level,
        })
    }
}

fn parse_socket_addr(name: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|error| Error::Config(format!("{name} must be host:port: {error}")))
}

fn parse_name(name: &str, value: &str) -> Result<Name> {
    let mut parsed = Name::from_ascii(value.trim())
        .map_err(|error| Error::Config(format!("{name} must be a DNS name: {error}")))?;
    parsed.set_fqdn(true);
    Ok(parsed.to_lowercase())
}

fn parse_tsig_algorithm(value: &str) -> Result<TsigAlgorithm> {
    match value.trim().to_ascii_lowercase().as_str() {
        "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
        "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
        other => Err(Error::Config(format!(
            "TSIG_ALGORITHM must be hmac-sha256, hmac-sha384, or hmac-sha512; got {other}"
        ))),
    }
}
