use hickory_proto::rr::Name;

use crate::config::AppConfig;

use super::DnsError;

pub fn normalize_owner_name(name: &Name, config: &AppConfig) -> Result<Name, DnsError> {
    let mut normalized = name.to_lowercase();
    normalized.set_fqdn(true);

    if normalized == config.dns_zone {
        return Err(DnsError::RecordRejected(
            "zone apex records are not allowed".to_string(),
        ));
    }

    if !config.dns_zone.zone_of(&normalized) {
        return Err(DnsError::ZoneRejected(format!(
            "{normalized} is outside DNS_ZONE"
        )));
    }

    if !config.allowed_record_suffix.zone_of(&normalized) {
        return Err(DnsError::RecordRejected(format!(
            "{normalized} is outside ALLOWED_RECORD_SUFFIX"
        )));
    }

    if normalized.is_wildcard() {
        return Err(DnsError::RecordRejected(
            "wildcard records are not allowed".to_string(),
        ));
    }

    if first_label_starts_with_underscore(&normalized) {
        return Err(DnsError::RecordRejected(
            "records whose first label starts with underscore are not allowed".to_string(),
        ));
    }

    Ok(normalized)
}

fn first_label_starts_with_underscore(name: &Name) -> bool {
    name.iter()
        .next()
        .is_some_and(|label| label.first().is_some_and(|byte| *byte == b'_'))
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::Name;

    use super::first_label_starts_with_underscore;

    #[test]
    fn detects_leading_underscore_label() {
        let name = Name::from_ascii("_svc.example.internal.").unwrap();
        assert!(first_label_starts_with_underscore(&name));
    }

    #[test]
    fn permits_non_leading_underscore_byte() {
        let name = Name::from_ascii("host_name.example.internal.").unwrap();
        assert!(!first_label_starts_with_underscore(&name));
    }
}
