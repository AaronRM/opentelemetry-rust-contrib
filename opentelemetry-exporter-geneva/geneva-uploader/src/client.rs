//! High-level GenevaClient for user code. Wraps config_service and ingestion_service.

use crate::config_service::client::{AuthMethod, GenevaConfigClient, GenevaConfigClientConfig};
// ManagedIdentitySelector removed; no re-export needed.
use crate::ingestion_service::uploader::{GenevaUploader, GenevaUploaderConfig};
use crate::payload_encoder::otlp_encoder::MetadataFields;
use crate::payload_encoder::otlp_encoder::OtlpEncoder;
use opentelemetry_proto::tonic::logs::v1::ResourceLogs;
use opentelemetry_proto::tonic::trace::v1::ResourceSpans;
use std::sync::Arc;
use tracing::{debug, info};

/// Public batch type (already LZ4 chunked compressed).
/// Produced by `OtlpEncoder::encode_log_batch` and returned to callers.
#[derive(Debug, Clone)]
pub struct EncodedBatch {
    pub event_name: String,
    pub data: Vec<u8>,
    pub metadata: crate::payload_encoder::central_blob::BatchMetadata,
    pub row_count: usize,
}

/// A pre-serialized row for the raw batch encoding path.
/// Used with [`GenevaClient::encode_raw_batch`] for callers that provide
/// field values directly rather than going through the OTLP pipeline.
#[derive(Debug, Clone)]
pub struct RawRow {
    /// Timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: u64,
    /// Pre-serialized Bond Simple Binary row data (field values in schema order)
    pub row_data: Vec<u8>,
}

/// Configuration for GenevaClient (user-facing)
#[derive(Clone, Debug)]
pub struct GenevaClientConfig {
    pub endpoint: String,
    pub environment: String,
    pub account: String,
    pub namespace: String,
    pub region: String,
    pub config_major_version: u32,
    pub auth_method: AuthMethod,
    pub tenant: String,
    pub role_name: String,
    pub role_instance: String,
    pub msi_resource: Option<String>, // Required for Managed Identity variants
                                      // Add event name/version here if constant, or per-upload if you want them per call.
}

/// Main user-facing client for Geneva ingestion.
#[derive(Clone)]
pub struct GenevaClient {
    uploader: Arc<GenevaUploader>,
    encoder: OtlpEncoder,
    metadata_fields: MetadataFields,
}

impl GenevaClient {
    pub fn new(cfg: GenevaClientConfig) -> Result<Self, String> {
        info!(
            name: "client.new",
            target: "geneva-uploader",
            endpoint = %cfg.endpoint,
            namespace = %cfg.namespace,
            account = %cfg.account,
            "Initializing GenevaClient"
        );

        // Validate MSI resource presence for managed identity variants
        match cfg.auth_method {
            AuthMethod::SystemManagedIdentity
            | AuthMethod::UserManagedIdentity { .. }
            | AuthMethod::UserManagedIdentityByObjectId { .. }
            | AuthMethod::UserManagedIdentityByResourceId { .. } => {
                if cfg.msi_resource.is_none() {
                    debug!(
                        name: "client.new.validate_msi_resource",
                        target: "geneva-uploader",
                        "Validation failed: msi_resource must be provided for managed identity auth"
                    );
                    return Err(
                        "msi_resource must be provided for managed identity auth".to_string()
                    );
                }
            }
            AuthMethod::Certificate { .. } => {}
            AuthMethod::WorkloadIdentity { .. } => {}
            #[cfg(feature = "mock_auth")]
            AuthMethod::MockAuth => {}
        }
        let config_client_config = GenevaConfigClientConfig {
            endpoint: cfg.endpoint,
            environment: cfg.environment.clone(),
            account: cfg.account,
            namespace: cfg.namespace.clone(),
            region: cfg.region,
            config_major_version: cfg.config_major_version,
            auth_method: cfg.auth_method,
            msi_resource: cfg.msi_resource,
        };
        let config_client =
            Arc::new(GenevaConfigClient::new(config_client_config).map_err(|e| {
                debug!(
                    name: "client.new.config_client_init",
                    target: "geneva-uploader",
                    error = %e,
                    "GenevaConfigClient init failed"
                );
                format!("GenevaConfigClient init failed: {e}")
            })?);

        let source_identity = format!(
            "Tenant={}/Role={}/RoleInstance={}",
            cfg.tenant, cfg.role_name, cfg.role_instance
        );

        let config_version = format!("Ver{}v0", cfg.config_major_version);

        // Create metadata fields that will appear as Bond schema fields in Geneva
        let metadata_fields = MetadataFields::new(
            cfg.environment,
            config_version.clone(),
            cfg.tenant,
            cfg.role_name,
            cfg.role_instance,
            cfg.namespace,
            config_version,
        );

        let uploader_config = GenevaUploaderConfig {
            namespace: metadata_fields.namespace.clone(),
            source_identity,
            environment: metadata_fields.env_name.clone(),
            config_version: metadata_fields.event_version.clone(),
        };

        let uploader =
            GenevaUploader::from_config_client(config_client, uploader_config).map_err(|e| {
                debug!(
                    name: "client.new.uploader_init",
                    target: "geneva-uploader",
                    error = %e,
                    "GenevaUploader init failed"
                );
                format!("GenevaUploader init failed: {e}")
            })?;

        info!(
            name: "client.new.complete",
            target: "geneva-uploader",
            "GenevaClient initialized successfully"
        );

        Ok(Self {
            uploader: Arc::new(uploader),
            encoder: OtlpEncoder::new(),
            metadata_fields,
        })
    }

    /// Encode OTLP logs into LZ4 chunked compressed batches.
    pub fn encode_and_compress_logs(
        &self,
        logs: &[ResourceLogs],
    ) -> Result<Vec<EncodedBatch>, String> {
        debug!(
            name: "client.encode_and_compress_logs",
            target: "geneva-uploader",
            resource_logs_count = logs.len(),
            "Encoding and compressing resource logs"
        );

        let log_iter = logs
            .iter()
            .flat_map(|resource_log| resource_log.scope_logs.iter())
            .flat_map(|scope_log| scope_log.log_records.iter());

        self.encoder
            .encode_log_batch(log_iter, &self.metadata_fields)
            .map_err(|e| {
                debug!(
                    name: "client.encode_and_compress_logs.error",
                    target: "geneva-uploader",
                    error = %e,
                    "Log compression failed"
                );
                format!("Compression failed: {e}")
            })
    }

    /// Encode OTLP spans into LZ4 chunked compressed batches.
    pub fn encode_and_compress_spans(
        &self,
        spans: &[ResourceSpans],
    ) -> Result<Vec<EncodedBatch>, String> {
        debug!(
            name: "client.encode_and_compress_spans",
            target: "geneva-uploader",
            resource_spans_count = spans.len(),
            "Encoding and compressing resource spans"
        );

        let span_iter = spans
            .iter()
            .flat_map(|resource_span| resource_span.scope_spans.iter())
            .flat_map(|scope_span| scope_span.spans.iter());

        self.encoder
            .encode_span_batch(span_iter, &self.metadata_fields)
            .map_err(|e| {
                debug!(
                    name: "client.encode_and_compress_spans.error",
                    target: "geneva-uploader",
                    error = %e,
                    "Span compression failed"
                );
                format!("Compression failed: {e}")
            })
    }

    /// Encode a batch of pre-serialized rows sharing a single schema.
    ///
    /// This is the "raw" encoding path for callers that handle their own
    /// field-value-to-Bond-row serialization (e.g., the FFI mapped-batch API).
    /// The library handles Bond schema assembly, CentralBlob construction,
    /// LZ4 compression, and upload metadata.
    ///
    /// All rows must match the provided field definitions (same count, same order).
    pub fn encode_raw_batch(
        &self,
        fields: &[crate::payload_encoder::bond_encoder::FieldDef],
        event_name: &str,
        level: u8,
        rows: &[RawRow],
    ) -> Result<Vec<EncodedBatch>, String> {
        use crate::payload_encoder::bond_encoder::BondEncodedSchema;
        use crate::payload_encoder::central_blob::{
            CentralBlob, CentralEventEntry, CentralSchemaEntry,
        };
        use crate::payload_encoder::lz4_chunked_compression::lz4_chunked_compression;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Build single schema
        let schema = BondEncodedSchema::from_fields(
            "CustomRecord",
            &self.metadata_fields.namespace,
            fields,
        );
        let schema_md5 = md5::compute(schema.as_bytes()).0;

        let schema_entry = CentralSchemaEntry {
            id: 1,
            md5: schema_md5,
            schema,
            fields: fields.to_vec(),
        };

        let schema_ids = format!("{:x}", md5::Digest(schema_md5));

        // Build events and track timestamp range
        let event_name_arc = Arc::new(event_name.to_string());
        let mut start_time = u64::MAX;
        let mut end_time = 0u64;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            if row.timestamp_ns != 0 {
                start_time = start_time.min(row.timestamp_ns);
                end_time = end_time.max(row.timestamp_ns);
            }
            events.push(CentralEventEntry {
                schema_id: 1,
                level,
                event_name: Arc::clone(&event_name_arc),
                row: row.row_data.clone(),
            });
        }

        // Build blob
        let blob = CentralBlob {
            version: 1,
            format: 2,
            metadata: self.metadata_fields.metadata_string().to_owned(),
            schemas: vec![schema_entry],
            events,
        };

        // Compress
        let uncompressed = blob.to_bytes();
        let compressed = lz4_chunked_compression(&uncompressed).map_err(|e| {
            debug!(
                name: "client.encode_raw_batch.compress_error",
                target: "geneva-uploader",
                event_name = %event_name,
                error = %e,
                "LZ4 compression failed"
            );
            format!("compression failed: {e}")
        })?;

        debug!(
            name: "client.encode_raw_batch",
            target: "geneva-uploader",
            event_name = %event_name,
            rows = rows.len(),
            uncompressed_size = uncompressed.len(),
            compressed_size = compressed.len(),
            "Encoded raw batch"
        );

        Ok(vec![EncodedBatch {
            event_name: event_name.to_string(),
            data: compressed,
            metadata: crate::payload_encoder::central_blob::BatchMetadata {
                start_time: if start_time == u64::MAX {
                    0
                } else {
                    start_time
                },
                end_time,
                schema_ids,
            },
            row_count: rows.len(),
        }])
    }

    /// Upload a single compressed batch.
    /// This allows for granular control over uploads, including custom retry logic for individual batches.
    pub async fn upload_batch(&self, batch: &EncodedBatch) -> Result<(), String> {
        debug!(
            name: "client.upload_batch",
            target: "geneva-uploader",
            event_name = %batch.event_name,
            size = batch.data.len(),
            "Uploading batch"
        );

        self.uploader
            .upload(
                batch.data.clone(),
                &batch.event_name,
                &batch.metadata,
                batch.row_count,
            )
            .await
            .map(|_| {
                debug!(
                    name: "client.upload_batch.success",
                    target: "geneva-uploader",
                    event_name = %batch.event_name,
                    "Successfully uploaded batch"
                );
            })
            .map_err(|e| {
                debug!(
                    name: "client.upload_batch.error",
                    target: "geneva-uploader",
                    event_name = %batch.event_name,
                    error = %e,
                    "Geneva upload failed"
                );
                format!("Geneva upload failed: {e} Event: {}", batch.event_name)
            })
    }
}
