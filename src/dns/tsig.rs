use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::tsig::{
    TSIG, make_tsig_record, message_tbs, signed_bitmessage_to_buf,
};

use crate::config::AppConfig;

use super::DnsError;

#[derive(Debug, Clone)]
pub struct VerifiedTsig {
    request_mac: Vec<u8>,
}

pub fn verify_request(raw: &[u8], config: &AppConfig) -> Result<VerifiedTsig, DnsError> {
    let (message_for_mac, record) =
        signed_bitmessage_to_buf(raw, None, true).map_err(|_| DnsError::TsigFailed)?;
    let tsig = &record.data;

    if record.name != config.tsig_key_name || tsig.algorithm != config.tsig_algorithm {
        return Err(DnsError::TsigFailed);
    }

    config
        .tsig_algorithm
        .verify_mac(&config.tsig_secret, &message_for_mac, &tsig.mac)
        .map_err(|_| DnsError::TsigFailed)?;

    validate_time(tsig)?;

    Ok(VerifiedTsig {
        request_mac: tsig.mac.clone(),
    })
}

pub fn sign_response(
    response: &mut Message,
    verified: &VerifiedTsig,
    config: &AppConfig,
) -> Result<(), DnsError> {
    let now = current_unix_time()?;
    let pre_tsig = TSIG::new(
        config.tsig_algorithm.clone(),
        now,
        300,
        Vec::new(),
        response.metadata.id,
        None,
        Vec::new(),
    );

    let message_for_mac = response_tbs(response, &pre_tsig, &config.tsig_key_name, verified)?;
    let mac = config
        .tsig_algorithm
        .mac_data(&config.tsig_secret, &message_for_mac)
        .map_err(|error| DnsError::Encode(error.to_string()))?;
    let tsig_record = make_tsig_record(config.tsig_key_name.clone(), pre_tsig.set_mac(mac));

    response.set_signature(Box::new(tsig_record));
    Ok(())
}

fn response_tbs(
    response: &Message,
    pre_tsig: &TSIG,
    key_name: &hickory_proto::rr::Name,
    verified: &VerifiedTsig,
) -> Result<Vec<u8>, DnsError> {
    let message_without_request_mac = message_tbs(response, pre_tsig, key_name)
        .map_err(|error| DnsError::Encode(error.to_string()))?;
    let mut result =
        Vec::with_capacity(2 + verified.request_mac.len() + message_without_request_mac.len());
    result.extend_from_slice(
        &u16::try_from(verified.request_mac.len())
            .map_err(|_| DnsError::Encode("TSIG MAC is too large".to_string()))?
            .to_be_bytes(),
    );
    result.extend_from_slice(&verified.request_mac);
    result.extend_from_slice(&message_without_request_mac);
    Ok(result)
}

fn validate_time(tsig: &TSIG) -> Result<(), DnsError> {
    let now = current_unix_time()?;
    let earliest = tsig.time.saturating_sub(u64::from(tsig.fudge));
    let latest = tsig.time.saturating_add(u64::from(tsig.fudge));

    if now < earliest || now > latest {
        return Err(DnsError::TsigFailed);
    }

    Ok(())
}

fn current_unix_time() -> Result<u64, DnsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| DnsError::Encode(error.to_string()))
}
