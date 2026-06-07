pub mod rfc2136;
pub mod tsig;
pub mod validation;

use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::cloudflare::CloudflareClient;
use crate::config::AppConfig;
use crate::error::{Error, Result};

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("TSIG validation failed")]
    TsigFailed,

    #[error("not an RFC2136 update message")]
    NotUpdate,

    #[error("zone rejected: {0}")]
    ZoneRejected(String),

    #[error("record rejected: {0}")]
    RecordRejected(String),

    #[error("unsupported update operation: {0}")]
    UnsupportedOperation(String),

    #[error("response encoding failed: {0}")]
    Encode(String),
}

impl DnsError {
    fn response_code(&self) -> ResponseCode {
        match self {
            Self::Encode(_) => ResponseCode::FormErr,
            Self::TsigFailed
            | Self::NotUpdate
            | Self::ZoneRejected(_)
            | Self::RecordRejected(_)
            | Self::UnsupportedOperation(_) => ResponseCode::Refused,
        }
    }
}

pub async fn run(config: AppConfig, cloudflare: CloudflareClient) -> Result<()> {
    let config = Arc::new(config);
    let cloudflare = Arc::new(cloudflare);

    let udp_task = tokio::spawn(serve_udp(config.clone(), cloudflare.clone()));
    let tcp_task = tokio::spawn(serve_tcp(config.clone(), cloudflare.clone()));

    tokio::select! {
        result = udp_task => result??,
        result = tcp_task => result??,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            info!("shutdown signal received");
        }
    }

    Ok(())
}

async fn serve_udp(config: Arc<AppConfig>, cloudflare: Arc<CloudflareClient>) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(config.listen_udp).await?);
    info!(addr = %config.listen_udp, "udp listener ready");

    loop {
        let mut buffer = vec![0_u8; 65_535];
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        buffer.truncate(len);

        let socket = socket.clone();
        let config = config.clone();
        let cloudflare = cloudflare.clone();

        tokio::spawn(async move {
            let response = handle_wire(&buffer, config, cloudflare).await;
            if let Err(error) = socket.send_to(&response, peer).await {
                warn!(%peer, %error, "udp response send failed");
            }
        });
    }
}

async fn serve_tcp(config: Arc<AppConfig>, cloudflare: Arc<CloudflareClient>) -> Result<()> {
    let listener = TcpListener::bind(config.listen_tcp).await?;
    info!(addr = %config.listen_tcp, "tcp listener ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        let cloudflare = cloudflare.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_tcp_connection(stream, config, cloudflare).await {
                warn!(%peer, %error, "tcp connection finished with error");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    config: Arc<AppConfig>,
    cloudflare: Arc<CloudflareClient>,
) -> Result<()> {
    loop {
        let len = match stream.read_u16().await {
            Ok(len) => usize::from(len),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(Error::Io(error)),
        };

        if len == 0 {
            continue;
        }

        let mut buffer = vec![0_u8; len];
        stream.read_exact(&mut buffer).await?;

        let response = handle_wire(&buffer, config.clone(), cloudflare.clone()).await;
        let response_len = u16::try_from(response.len()).map_err(|_| {
            Error::Dns(DnsError::Encode(
                "encoded DNS response exceeds TCP length field".to_string(),
            ))
        })?;
        stream.write_u16(response_len).await?;
        stream.write_all(&response).await?;
    }
}

async fn handle_wire(
    raw: &[u8],
    config: Arc<AppConfig>,
    cloudflare: Arc<CloudflareClient>,
) -> Vec<u8> {
    let request = match Message::from_vec(raw) {
        Ok(message) => message,
        Err(error) => {
            let response = fallback_response(raw, ResponseCode::FormErr);
            warn!(%error, "dns message parse failed");
            return response;
        }
    };

    let verified_tsig = match tsig::verify_request(raw, &config) {
        Ok(verified) => verified,
        Err(error) => {
            warn!(%error, "tsig validation failed");
            let response = build_response(&request, ResponseCode::Refused);
            return encode_response(response, None, &config, raw);
        }
    };

    let changes = match rfc2136::extract_changes(&request, &config) {
        Ok(changes) => changes,
        Err(error) => {
            warn!(%error, "dns update refused");
            let response = build_response(&request, error.response_code());
            return encode_response(response, Some(&verified_tsig), &config, raw);
        }
    };

    for change in changes {
        debug!(?change, "applying dns change");
        let result = match change {
            rfc2136::DnsChange::Upsert {
                name,
                kind,
                contents,
            } => {
                cloudflare
                    .upsert_rrset(&name, kind, &contents, config.default_ttl)
                    .await
            }
            rfc2136::DnsChange::DeleteRrset { name, kind } => {
                cloudflare.delete_rrset(&name, kind).await
            }
            rfc2136::DnsChange::DeleteRecord {
                name,
                kind,
                content,
            } => cloudflare.delete_record(&name, kind, &content).await,
        };

        if let Err(error) = result {
            error!(%error, "cloudflare api request failed");
            let response = build_response(&request, ResponseCode::ServFail);
            return encode_response(response, Some(&verified_tsig), &config, raw);
        }
    }

    let response = build_response(&request, ResponseCode::NoError);
    encode_response(response, Some(&verified_tsig), &config, raw)
}

fn build_response(request: &Message, response_code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.message_type = MessageType::Response;
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.response_code = response_code;

    if let Some(zone) = request.queries.first() {
        response.add_query(zone.clone());
    }

    response
}

fn encode_response(
    mut response: Message,
    verified_tsig: Option<&tsig::VerifiedTsig>,
    config: &AppConfig,
    request_wire: &[u8],
) -> Vec<u8> {
    if let Some(verified_tsig) = verified_tsig
        && let Err(error) = tsig::sign_response(&mut response, verified_tsig, config)
    {
        warn!(%error, "response signing failed");
    }

    response.to_vec().unwrap_or_else(|error| {
        warn!(%error, "response encode failed");
        fallback_response(request_wire, ResponseCode::ServFail)
    })
}

fn fallback_response(raw: &[u8], response_code: ResponseCode) -> Vec<u8> {
    let mut response = vec![0_u8; 12];
    if raw.len() >= 2 {
        response[0] = raw[0];
        response[1] = raw[1];
    }

    let opcode_bits = if raw.len() >= 3 { raw[2] & 0x78 } else { 0 };
    response[2] = 0x80 | opcode_bits;
    response[3] = response_code_to_u8(response_code);
    response
}

fn response_code_to_u8(code: ResponseCode) -> u8 {
    match code {
        ResponseCode::NoError => 0,
        ResponseCode::FormErr => 1,
        ResponseCode::ServFail => 2,
        ResponseCode::NXDomain => 3,
        ResponseCode::NotImp => 4,
        ResponseCode::Refused => 5,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_response_preserves_id_and_opcode() {
        let raw = [0x12, 0x34, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let response = fallback_response(&raw, ResponseCode::Refused);
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(response[2] & 0x78, 0x28);
        assert_eq!(response[3], 5);
    }
}
