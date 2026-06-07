use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DnsRecordKind {
    A,
    Aaaa,
}

impl DnsRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ApiEnvelope<T> {
    pub success: bool,
    pub errors: Vec<ApiError>,
    pub result: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub code: i64,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteResult {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct RecordRequest<'a> {
    #[serde(rename = "type")]
    pub record_type: &'a str,
    pub name: &'a str,
    pub content: &'a str,
    pub ttl: u32,
    pub proxied: bool,
}
