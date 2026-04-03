use crate::config_service::client::{GenevaConfigClient, GenevaConfigClientError};
use crate::payload_encoder::central_blob::BatchMetadata;
use reqwest::{header, Client};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::{debug, warn};
use url::form_urlencoded::byte_serialize;
use uuid::Uuid;

/// Maximum content size accepted by GIG (8 MB).
const GIG_MAX_CONTENT_LENGTH: usize = 8 * 1024 * 1024;

/// Classification of a GIG error for retry decisions.
///
/// Callers (e.g. the otap-dataflow Geneva exporter) use this to decide
/// whether to retry, drop, or refresh credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GigErrorKind {
    /// 400, 414 — malformed request. Never retry; drop the batch.
    BadRequest,
    /// 401 / 403 (non-40200) — authentication or authorization failure.
    /// Caller should invalidate cached credentials and retry once.
    AuthFailure,
    /// 403 + GIG error code 40200 — server directs fallback to Azure Storage.
    FallbackDirective,
    /// 408 / HTTP timeouts — transient; retry with backoff.
    Timeout,
    /// Connection/network errors (DNS, TLS, connection refused, etc.) — transient; retry with backoff.
    NetworkError,
    /// 429 — server is overloaded. Honour `Retry-After` if present.
    RateLimited,
    /// 5xx — server error; retry with backoff.
    ServerError,
    /// Payload exceeds GIG size limit. Never retry as-is.
    PayloadTooLarge,
    /// Any other unclassified error.
    Unknown,
}

impl GigErrorKind {
    /// Returns `true` when the request could succeed if retried
    /// (possibly after a delay or credential refresh).
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            GigErrorKind::AuthFailure
                | GigErrorKind::Timeout
                | GigErrorKind::NetworkError
                | GigErrorKind::RateLimited
                | GigErrorKind::ServerError
        )
    }
}

impl fmt::Display for GigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GigErrorKind::BadRequest => write!(f, "BadRequest"),
            GigErrorKind::AuthFailure => write!(f, "AuthFailure"),
            GigErrorKind::FallbackDirective => write!(f, "FallbackDirective"),
            GigErrorKind::Timeout => write!(f, "Timeout"),
            GigErrorKind::NetworkError => write!(f, "NetworkError"),
            GigErrorKind::RateLimited => write!(f, "RateLimited"),
            GigErrorKind::ServerError => write!(f, "ServerError"),
            GigErrorKind::PayloadTooLarge => write!(f, "PayloadTooLarge"),
            GigErrorKind::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Error types for the Geneva Uploader
#[derive(Debug, Error)]
pub(crate) enum GenevaUploaderError {
    #[error("HTTP error: {message}")]
    Http {
        message: String,
        is_timeout: bool,
    },
    #[error("JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Config service error: {0}")]
    ConfigClient(#[from] GenevaConfigClientError),
    /// Structured upload failure with GIG-specific classification.
    #[error("Upload failed ({kind}, status {status}): {message}")]
    UploadFailed {
        status: u16,
        message: String,
        /// Classified error kind for retry decisions.
        kind: GigErrorKind,
        /// `Retry-After` value from GIG (seconds), if present.
        retry_after: Option<Duration>,
        /// GIG internal error code from the response body, if present.
        gig_error_code: Option<u32>,
    },
    #[error("Payload too large ({size} bytes, limit {limit} bytes)")]
    PayloadTooLarge { size: usize, limit: usize },
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl GenevaUploaderError {
    /// Returns the [`GigErrorKind`] for this error.
    pub fn kind(&self) -> GigErrorKind {
        match self {
            GenevaUploaderError::UploadFailed { kind, .. } => *kind,
            GenevaUploaderError::PayloadTooLarge { .. } => GigErrorKind::PayloadTooLarge,
            GenevaUploaderError::Http { is_timeout, .. } => {
                if *is_timeout {
                    GigErrorKind::Timeout
                } else {
                    GigErrorKind::NetworkError
                }
            }
            GenevaUploaderError::ConfigClient(err) => classify_config_client_error(err),
            GenevaUploaderError::SerdeJson(_) => GigErrorKind::Unknown,
            GenevaUploaderError::InternalError(_) => GigErrorKind::Unknown,
        }
    }

    /// Returns `true` if the error is retryable per the GIG contract.
    pub fn is_retryable(&self) -> bool {
        self.kind().is_retryable()
    }

    /// Returns the `Retry-After` duration hint from GIG, if available.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            GenevaUploaderError::UploadFailed { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

impl From<reqwest::Error> for GenevaUploaderError {
    fn from(err: reqwest::Error) -> Self {
        use std::fmt::Write;
        let mut msg = String::new();
        write!(&mut msg, "{err}").ok();

        if let Some(url) = err.url() {
            write!(msg, ", url: {url}").ok();
        }
        if let Some(status) = err.status() {
            write!(msg, ", status: {status}").ok();
        }

        // Print high-level error types
        if err.is_timeout() {
            write!(&mut msg, ", kind: timeout").ok();
        } else if err.is_connect() {
            write!(&mut msg, ", kind: connect").ok();
        } else if err.is_body() {
            write!(&mut msg, ", kind: body").ok();
        } else if err.is_decode() {
            write!(&mut msg, ", kind: decode").ok();
        } else if err.is_request() {
            write!(&mut msg, ", kind: request").ok();
        }

        // Traverse the whole source chain for detail
        let mut source = err.source();
        let mut idx = 0;
        let mut found_io = false;
        while let Some(s) = source {
            write!(msg, ", cause[{idx}]: {s}").ok();

            // Surface io::ErrorKind if found
            if let Some(io_err) = s.downcast_ref::<std::io::Error>() {
                write!(msg, " (io::ErrorKind::{:?})", io_err.kind()).ok();
                found_io = true;
            }
            source = s.source();
            idx += 1;
        }

        if !found_io {
            write!(&mut msg, ", (no io::Error in source chain)").ok();
        }

        GenevaUploaderError::Http {
            message: msg,
            is_timeout: err.is_timeout(),
        }
    }
}

fn classify_config_client_error(err: &GenevaConfigClientError) -> GigErrorKind {
    match err {
        GenevaConfigClientError::Http(e) => {
            if e.is_timeout() {
                GigErrorKind::Timeout
            } else {
                GigErrorKind::NetworkError
            }
        }
        GenevaConfigClientError::RequestFailed { status, .. } => {
            classify_gig_error(*status, None)
        }
        GenevaConfigClientError::MsiAuth(_)
        | GenevaConfigClientError::WorkloadIdentityAuth(_)
        | GenevaConfigClientError::AuthInfoNotFound(_)
        | GenevaConfigClientError::JwtTokenError(_)
        | GenevaConfigClientError::Certificate(_)
        | GenevaConfigClientError::MonikerNotFound(_)
        | GenevaConfigClientError::SerdeJson(_)
        | GenevaConfigClientError::InternalError(_) => GigErrorKind::Unknown,
    }
}

pub(crate) type Result<T> = std::result::Result<T, GenevaUploaderError>;

/// Response from the ingestion API when submitting data
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IngestionResponse {
    /// Ticket ID for this ingestion (1PC: treat as committed immediately).
    pub(crate) ticket: String,
    #[serde(flatten)]
    #[allow(dead_code)]
    pub(crate) extra: HashMap<String, Value>,
}

/// Default HTTP request timeout in seconds.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Configuration for the Geneva Uploader
#[derive(Debug, Clone)]
pub(crate) struct GenevaUploaderConfig {
    pub namespace: String,
    pub source_identity: String,
    #[allow(dead_code)]
    pub environment: String,
    pub config_version: String,
    /// HTTP request timeout. Defaults to 30 seconds if `None`.
    pub request_timeout: Option<Duration>,
}

/// Client for uploading data to Geneva Ingestion Gateway (GIG)
#[derive(Debug, Clone)]
pub struct GenevaUploader {
    pub config_client: Arc<GenevaConfigClient>,
    pub config: GenevaUploaderConfig,
    pub http_client: Client,
}

impl GenevaUploader {
    /// Constructs a GenevaUploader by calling the GenevaConfigClient
    ///
    /// # Arguments
    /// * `config_client` - Initialized GenevaConfigClient
    /// * `uploader_config` - Static config (namespace, event, version, etc.)
    ///
    /// # Returns
    /// * `Result<GenevaUploader>` with authenticated client and resolved moniker/endpoint
    #[allow(dead_code)]
    pub(crate) fn from_config_client(
        config_client: Arc<GenevaConfigClient>,
        uploader_config: GenevaUploaderConfig,
    ) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let timeout = uploader_config
            .request_timeout
            .unwrap_or(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS));
        let client = Self::build_h1_client(headers, timeout)?;

        Ok(Self {
            config_client,
            config: uploader_config,
            http_client: client,
        })
    }

    fn build_h1_client(headers: header::HeaderMap, timeout: Duration) -> Result<Client> {
        Ok(Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .http1_only()
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .build()?)
    }

    /// Creates the GIG upload URI with required parameters
    #[allow(dead_code)]
    fn create_upload_uri(
        &self,
        monitoring_endpoint: &str,
        moniker: &str,
        data_size: usize,
        event_name: &str,
        metadata: &BatchMetadata,
        row_count: usize,
    ) -> Result<String> {
        // Get already formatted schema IDs and format timestamps using BatchMetadata methods
        let schema_ids = &metadata.schema_ids;
        let start_time_str = metadata.format_start_timestamp();
        let end_time_str = metadata.format_end_timestamp();

        // URL encode parameters
        // TODO - Maintain this as url-encoded in config service to avoid conversion here
        let encoded_monitoring_endpoint: String =
            byte_serialize(monitoring_endpoint.as_bytes()).collect();
        let encoded_source_identity: String =
            byte_serialize(self.config.source_identity.as_bytes()).collect();

        // Create a source unique ID - using a UUID to ensure uniqueness
        let source_unique_id = Uuid::new_v4();

        // Create the query string
        let mut query = String::with_capacity(512); // Preallocate enough space for the query string (decided based on expected size)
        write!(&mut query, "api/v1/ingestion/ingest?endpoint={}&moniker={}&namespace={}&event={}&version={}&sourceUniqueId={}&sourceIdentity={}&startTime={}&endTime={}&format=centralbond/lz4hc&dataSize={}&minLevel={}&schemaIds={}&rowCount={}",
            encoded_monitoring_endpoint,
            moniker,
            self.config.namespace,
            event_name,
            self.config.config_version,
            source_unique_id,
            encoded_source_identity,
            start_time_str,
            end_time_str,
            data_size,
            2,
            schema_ids,
            row_count
        ).map_err(|e| GenevaUploaderError::InternalError(format!("Failed to write query string: {e}")))?;
        Ok(query)
    }

    /// Uploads data to the ingestion gateway.
    ///
    /// On auth failures (401/403), this method automatically invalidates
    /// the cached GCS token so the next attempt fetches a fresh one.
    ///
    /// # Arguments
    /// * `data` - The encoded data to upload (already in the required format)
    /// * `event_name` - Name of the event
    /// * `metadata` - Batch metadata containing timestamps and schema information
    /// * `row_count` - Number of rows/events in the batch
    ///
    /// # Returns
    /// * `Result<IngestionResponse>` - The response containing the ticket ID or an error.
    ///   On failure the [`GenevaUploaderError`] carries a [`GigErrorKind`] so
    ///   callers can decide whether to retry, drop, or refresh credentials.
    #[allow(dead_code)]
    pub(crate) async fn upload(
        &self,
        data: Vec<u8>,
        event_name: &str,
        metadata: &BatchMetadata,
        row_count: usize,
    ) -> Result<IngestionResponse> {
        debug!(
            name: "uploader.upload",
            target: "geneva-uploader",
            event_name = %event_name,
            size = data.len(),
            "Starting upload"
        );

        // --- Pre-flight: reject payloads that GIG will refuse -----------
        if data.len() > GIG_MAX_CONTENT_LENGTH {
            warn!(
                name: "uploader.upload.payload_too_large",
                target: "geneva-uploader",
                event_name = %event_name,
                size = data.len(),
                limit = GIG_MAX_CONTENT_LENGTH,
                "Payload exceeds GIG maximum content length"
            );
            return Err(GenevaUploaderError::PayloadTooLarge {
                size: data.len(),
                limit: GIG_MAX_CONTENT_LENGTH,
            });
        }

        // Always get fresh auth info
        let (auth_info, moniker_info, monitoring_endpoint) =
            self.config_client.get_ingestion_info().await?;
        let data_size = data.len();
        let upload_uri = self.create_upload_uri(
            &monitoring_endpoint,
            &moniker_info.name,
            data_size,
            event_name,
            metadata,
            row_count,
        )?;
        let full_url = format!(
            "{}/{}",
            auth_info.endpoint.trim_end_matches('/'),
            upload_uri
        );

        debug!(
            name: "uploader.upload.post",
            target: "geneva-uploader",
            event_name = %event_name,
            moniker = %moniker_info.name,
            "Posting to ingestion gateway"
        );

        // Send the upload request
        let response = self
            .http_client
            .post(&full_url)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_info.auth_token),
            )
            .body(data)
            .send()
            .await?;

        let status = response.status();

        // --- Extract Retry-After before consuming the body -------------
        let retry_after = parse_retry_after(response.headers());

        let body = response.text().await?;

        if status == reqwest::StatusCode::ACCEPTED {
            let ingest_response: IngestionResponse = serde_json::from_str(&body).map_err(|e| {
                debug!(
                    name: "uploader.upload.parse_error",
                    target: "geneva-uploader",
                    error = %e,
                    "Failed to parse ingestion response"
                );
                GenevaUploaderError::SerdeJson(e)
            })?;

            debug!(
                name: "uploader.upload.success",
                target: "geneva-uploader",
                event_name = %event_name,
                ticket = %ingest_response.ticket,
                "Upload successful"
            );

            Ok(ingest_response)
        } else {
            // --- Classify the error per the GIG contract ----------------
            let status_code = status.as_u16();
            let gig_error_code = parse_gig_error_code(&body);
            let kind = classify_gig_error(status_code, gig_error_code);

            debug!(
                name: "uploader.upload.failed",
                target: "geneva-uploader",
                event_name = %event_name,
                status = status_code,
                kind = %kind,
                gig_error_code = ?gig_error_code,
                retry_after = ?retry_after,
                body = %body,
                "Upload failed"
            );

            // On auth failures, invalidate the cached GCS token so the
            // next attempt (driven by the retry processor) fetches a
            // fresh one instead of re-using the stale token.
            //
            // NOTE: There is a benign TOCTOU race here — a concurrent
            // upload may have already refreshed the cache between our
            // failure and this invalidation, causing one extra config-
            // service round-trip on the next attempt.
            if kind == GigErrorKind::AuthFailure {
                warn!(
                    name: "uploader.upload.auth_failure",
                    target: "geneva-uploader",
                    status = status_code,
                    "Auth failure — invalidating cached GCS token"
                );
                self.config_client.invalidate_cache();
            }

            Err(GenevaUploaderError::UploadFailed {
                status: status_code,
                message: body,
                kind,
                retry_after,
                gig_error_code,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// GIG response helpers
// ---------------------------------------------------------------------------

/// Parse the `Retry-After` header as either a delta-seconds value or
/// an HTTP-date, per RFC 7231 Section 7.1.3.
/// 
/// GIG-Warm normally returns delta-seconds, but support both forms
/// for robustness and future compatibility.
///
/// Supports both HTTP forms:
/// * delta-seconds (e.g. `120`)
/// * HTTP-date (e.g. `Wed, 21 Oct 2015 07:28:00 GMT`)
///
/// If the header is absent or unparseable we return `None`.
fn parse_retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_retry_after_value(s, SystemTime::now()))
}

fn parse_retry_after_value(raw: &str, now: SystemTime) -> Option<Duration> {
    let trimmed = raw.trim();

    // RFC: Retry-After may be delta-seconds.
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // RFC: Retry-After may also be an HTTP-date.
    let retry_at = chrono::DateTime::parse_from_rfc2822(trimmed).ok()?;
    let retry_at_utc: chrono::DateTime<chrono::Utc> = retry_at.with_timezone(&chrono::Utc);
    let retry_at_system: SystemTime = retry_at_utc.into();

    // If the server-provided date is in the past, retry immediately.
    Some(
        retry_at_system
            .duration_since(now)
            .unwrap_or(Duration::from_secs(0)),
    )
}

/// Try to extract the GIG internal error code from a JSON error body.
///
/// GIG error responses use the shape `{"Error":{"Code":<u32>, ...}}`.
fn parse_gig_error_code(body: &str) -> Option<u32> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("Error")?.get("Code")?.as_u64())
        .and_then(|c| u32::try_from(c).ok())
}

/// Classify an HTTP status + optional GIG error code into a [`GigErrorKind`].
fn classify_gig_error(status: u16, gig_error_code: Option<u32>) -> GigErrorKind {
    match status {
        400 | 414 => GigErrorKind::BadRequest,
        401 => GigErrorKind::AuthFailure,
        403 => {
            if gig_error_code == Some(40200) {
                GigErrorKind::FallbackDirective
            } else {
                GigErrorKind::AuthFailure
            }
        }
        408 => GigErrorKind::Timeout,
        429 => GigErrorKind::RateLimited,
        500..=599 => GigErrorKind::ServerError,
        _ => GigErrorKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // classify_gig_error
    // ---------------------------------------------------------------

    #[test]
    fn classify_400_as_bad_request() {
        assert_eq!(classify_gig_error(400, None), GigErrorKind::BadRequest);
    }

    #[test]
    fn classify_414_as_bad_request() {
        assert_eq!(classify_gig_error(414, None), GigErrorKind::BadRequest);
    }

    #[test]
    fn classify_401_as_auth_failure() {
        assert_eq!(classify_gig_error(401, None), GigErrorKind::AuthFailure);
    }

    #[test]
    fn classify_403_as_auth_failure() {
        assert_eq!(classify_gig_error(403, None), GigErrorKind::AuthFailure);
    }

    #[test]
    fn classify_403_with_40200_as_fallback_directive() {
        assert_eq!(
            classify_gig_error(403, Some(40200)),
            GigErrorKind::FallbackDirective
        );
    }

    #[test]
    fn classify_403_with_other_code_as_auth_failure() {
        assert_eq!(
            classify_gig_error(403, Some(40300)),
            GigErrorKind::AuthFailure
        );
    }

    #[test]
    fn classify_408_as_timeout() {
        assert_eq!(classify_gig_error(408, None), GigErrorKind::Timeout);
    }

    #[test]
    fn classify_429_as_rate_limited() {
        assert_eq!(classify_gig_error(429, None), GigErrorKind::RateLimited);
    }

    #[test]
    fn classify_500_as_server_error() {
        assert_eq!(classify_gig_error(500, None), GigErrorKind::ServerError);
    }

    #[test]
    fn classify_503_as_server_error() {
        assert_eq!(classify_gig_error(503, None), GigErrorKind::ServerError);
    }

    #[test]
    fn classify_599_as_server_error() {
        assert_eq!(classify_gig_error(599, None), GigErrorKind::ServerError);
    }

    #[test]
    fn classify_unknown_status() {
        assert_eq!(classify_gig_error(418, None), GigErrorKind::Unknown);
    }

    // ---------------------------------------------------------------
    // GigErrorKind::is_retryable
    // ---------------------------------------------------------------

    #[test]
    fn bad_request_is_not_retryable() {
        assert!(!GigErrorKind::BadRequest.is_retryable());
    }

    #[test]
    fn fallback_directive_is_not_retryable() {
        assert!(!GigErrorKind::FallbackDirective.is_retryable());
    }

    #[test]
    fn payload_too_large_is_not_retryable() {
        assert!(!GigErrorKind::PayloadTooLarge.is_retryable());
    }

    #[test]
    fn auth_failure_is_retryable() {
        assert!(GigErrorKind::AuthFailure.is_retryable());
    }

    #[test]
    fn timeout_is_retryable() {
        assert!(GigErrorKind::Timeout.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(GigErrorKind::RateLimited.is_retryable());
    }

    #[test]
    fn server_error_is_retryable() {
        assert!(GigErrorKind::ServerError.is_retryable());
    }

    #[test]
    fn unknown_is_not_retryable() {
        assert!(!GigErrorKind::Unknown.is_retryable());
    }

    #[test]
    fn network_error_is_retryable() {
        assert!(GigErrorKind::NetworkError.is_retryable());
    }

    // ---------------------------------------------------------------
    // parse_retry_after
    // ---------------------------------------------------------------

    #[test]
    fn parse_retry_after_present() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "120".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_retry_after_with_whitespace() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "  60  ".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_retry_after_missing() {
        let headers = header::HeaderMap::new();
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_non_numeric() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "not-a-number".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_zero() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "0".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_retry_after_http_date_future() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let header_value = "Mon, 12 Jan 1970 13:48:40 GMT"; // +120s from `now`
        assert_eq!(
            parse_retry_after_value(header_value, now),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn parse_retry_after_http_date_past() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let header_value = "Mon, 12 Jan 1970 13:45:40 GMT"; // -60s from `now`
        assert_eq!(
            parse_retry_after_value(header_value, now),
            Some(Duration::from_secs(0))
        );
    }

    #[test]
    fn parse_retry_after_http_date_invalid() {
        let now = SystemTime::UNIX_EPOCH;
        assert_eq!(parse_retry_after_value("not-a-date", now), None);
    }

    // ---------------------------------------------------------------
    // parse_gig_error_code
    // ---------------------------------------------------------------

    #[test]
    fn parse_gig_error_code_present() {
        let body = r#"{"Error":{"Code":40200,"Message":"Blacklisted"}}"#;
        assert_eq!(parse_gig_error_code(body), Some(40200));
    }

    #[test]
    fn parse_gig_error_code_missing_error_field() {
        let body = r#"{"SomethingElse":"value"}"#;
        assert_eq!(parse_gig_error_code(body), None);
    }

    #[test]
    fn parse_gig_error_code_missing_code_field() {
        let body = r#"{"Error":{"Message":"oops"}}"#;
        assert_eq!(parse_gig_error_code(body), None);
    }

    #[test]
    fn parse_gig_error_code_invalid_json() {
        assert_eq!(parse_gig_error_code("not json"), None);
    }

    #[test]
    fn parse_gig_error_code_empty_body() {
        assert_eq!(parse_gig_error_code(""), None);
    }

    // ---------------------------------------------------------------
    // GenevaUploaderError helper methods
    // ---------------------------------------------------------------

    #[test]
    fn upload_failed_error_exposes_kind_and_retry_after() {
        let err = GenevaUploaderError::UploadFailed {
            status: 429,
            message: "overloaded".into(),
            kind: GigErrorKind::RateLimited,
            retry_after: Some(Duration::from_secs(60)),
            gig_error_code: None,
        };
        assert_eq!(err.kind(), GigErrorKind::RateLimited);
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn payload_too_large_error_is_not_retryable() {
        let err = GenevaUploaderError::PayloadTooLarge {
            size: 10_000_000,
            limit: GIG_MAX_CONTENT_LENGTH,
        };
        assert_eq!(err.kind(), GigErrorKind::PayloadTooLarge);
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn http_error_classified_as_network_error() {
        let err = GenevaUploaderError::Http {
            message: "connection reset".into(),
            is_timeout: false,
        };
        assert_eq!(err.kind(), GigErrorKind::NetworkError);
        assert!(err.is_retryable());
    }

    #[test]
    fn http_timeout_error_classified_as_timeout() {
        let err = GenevaUploaderError::Http {
            message: "request timed out".into(),
            is_timeout: true,
        };
        assert_eq!(err.kind(), GigErrorKind::Timeout);
        assert!(err.is_retryable());
    }

    #[test]
    fn config_client_5xx_error_is_retryable() {
        let err = GenevaUploaderError::ConfigClient(GenevaConfigClientError::RequestFailed {
            status: 503,
            message: "service unavailable".into(),
        });
        assert_eq!(err.kind(), GigErrorKind::ServerError);
        assert!(err.is_retryable());
    }

    #[test]
    fn bad_request_error_is_not_retryable() {
        let err = GenevaUploaderError::UploadFailed {
            status: 400,
            message: "invalid moniker".into(),
            kind: GigErrorKind::BadRequest,
            retry_after: None,
            gig_error_code: None,
        };
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    // ---------------------------------------------------------------
    // GIG_MAX_CONTENT_LENGTH constant
    // ---------------------------------------------------------------

    #[test]
    fn max_content_length_is_8mb() {
        assert_eq!(GIG_MAX_CONTENT_LENGTH, 8 * 1024 * 1024);
    }

    // ---------------------------------------------------------------
    // GigErrorKind::Display
    // ---------------------------------------------------------------

    #[test]
    fn error_kind_display() {
        assert_eq!(format!("{}", GigErrorKind::BadRequest), "BadRequest");
        assert_eq!(format!("{}", GigErrorKind::RateLimited), "RateLimited");
        assert_eq!(format!("{}", GigErrorKind::NetworkError), "NetworkError");
        assert_eq!(
            format!("{}", GigErrorKind::FallbackDirective),
            "FallbackDirective"
        );
    }
}
