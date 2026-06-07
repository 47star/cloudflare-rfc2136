use std::collections::HashSet;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::warn;

use super::model::{ApiEnvelope, ApiError, DeleteResult, DnsRecord, DnsRecordKind, RecordRequest};

const BASE_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Clone)]
pub struct CloudflareClient {
    http: Client,
    zone_id: String,
    api_token: String,
}

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("failed to create HTTP client: {0}")]
    ClientBuild(reqwest::Error),

    #[error("HTTP request failed for {operation}: {source}")]
    Http {
        operation: &'static str,
        #[source]
        source: reqwest::Error,
    },

    #[error(
        "Cloudflare API error for {operation}: status={status}, errors={}",
        format_api_errors(errors)
    )]
    Api {
        operation: &'static str,
        status: StatusCode,
        errors: Vec<ApiError>,
    },

    #[error("Cloudflare API response parse failed for {operation}: {source}")]
    Parse {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

impl CloudflareClient {
    pub fn new(zone_id: String, api_token: String) -> Result<Self, CloudflareError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!(
                "cloudflare-ddns-rfc2136/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(CloudflareError::ClientBuild)?;

        Ok(Self {
            http,
            zone_id,
            api_token,
        })
    }

    pub async fn upsert_rrset(
        &self,
        name: &str,
        kind: DnsRecordKind,
        contents: &[String],
        ttl: u32,
    ) -> Result<(), CloudflareError> {
        let desired = dedupe(contents);
        let existing = self.list_records(kind, name).await?;
        let mut used_ids = HashSet::new();

        for content in &desired {
            if let Some(record) = existing
                .iter()
                .find(|record| record.content == *content && !used_ids.contains(&record.id))
            {
                used_ids.insert(record.id.clone());
                if record.ttl != ttl || record.proxied.unwrap_or(false) {
                    self.update_record(&record.id, name, kind, content, ttl)
                        .await?;
                }
                continue;
            }

            if let Some(record) = existing
                .iter()
                .find(|record| !used_ids.contains(&record.id))
            {
                used_ids.insert(record.id.clone());
                self.update_record(&record.id, name, kind, content, ttl)
                    .await?;
            } else {
                self.create_record(name, kind, content, ttl).await?;
            }
        }

        for record in existing {
            if !used_ids.contains(&record.id) {
                self.delete_record_by_id(&record.id).await?;
            }
        }

        Ok(())
    }

    pub async fn delete_rrset(
        &self,
        name: &str,
        kind: DnsRecordKind,
    ) -> Result<(), CloudflareError> {
        for record in self.list_records(kind, name).await? {
            self.delete_record_by_id(&record.id).await?;
        }
        Ok(())
    }

    pub async fn delete_record(
        &self,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
    ) -> Result<(), CloudflareError> {
        for record in self.list_records(kind, name).await? {
            if record.content == content {
                self.delete_record_by_id(&record.id).await?;
            }
        }
        Ok(())
    }

    async fn list_records(
        &self,
        kind: DnsRecordKind,
        name: &str,
    ) -> Result<Vec<DnsRecord>, CloudflareError> {
        let url = self.records_url();
        let request = self.http.get(url).bearer_auth(&self.api_token).query(&[
            ("type", kind.as_str()),
            ("name", cloudflare_name(name).as_str()),
        ]);

        self.send(request, "list_records").await
    }

    async fn create_record(
        &self,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
        ttl: u32,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordRequest {
            record_type: kind.as_str(),
            name: &cloudflare_name(name),
            content,
            ttl,
            proxied: false,
        };
        let request = self
            .http
            .post(self.records_url())
            .bearer_auth(&self.api_token)
            .json(&body);

        self.send(request, "create_record").await
    }

    async fn update_record(
        &self,
        id: &str,
        name: &str,
        kind: DnsRecordKind,
        content: &str,
        ttl: u32,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordRequest {
            record_type: kind.as_str(),
            name: &cloudflare_name(name),
            content,
            ttl,
            proxied: false,
        };
        let request = self
            .http
            .put(format!("{}/{}", self.records_url(), id))
            .bearer_auth(&self.api_token)
            .json(&body);

        self.send(request, "update_record").await
    }

    async fn delete_record_by_id(&self, id: &str) -> Result<(), CloudflareError> {
        let request = self
            .http
            .delete(format!("{}/{}", self.records_url(), id))
            .bearer_auth(&self.api_token);

        let result: DeleteResult = self.send(request, "delete_record").await?;
        let _ = result.id;
        Ok(())
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        operation: &'static str,
    ) -> Result<T, CloudflareError> {
        let response = request
            .send()
            .await
            .map_err(|source| CloudflareError::Http { operation, source })?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        if status == StatusCode::TOO_MANY_REQUESTS {
            warn!(operation, retry_after, "cloudflare rate limit response");
        }

        let body = response
            .text()
            .await
            .map_err(|source| CloudflareError::Http { operation, source })?;

        let envelope: ApiEnvelope<T> = serde_json::from_str(&body)
            .map_err(|source| CloudflareError::Parse { operation, source })?;

        if !status.is_success() || !envelope.success {
            return Err(CloudflareError::Api {
                operation,
                status,
                errors: envelope.errors,
            });
        }

        Ok(envelope.result)
    }

    fn records_url(&self) -> String {
        format!("{BASE_URL}/zones/{}/dns_records", self.zone_id)
    }
}

fn cloudflare_name(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

fn dedupe(contents: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for content in contents {
        if seen.insert(content.clone()) {
            result.push(content.clone());
        }
    }
    result
}

fn format_api_errors(errors: &[ApiError]) -> String {
    if errors.is_empty() {
        return "none".to_string();
    }

    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}
