//! C-compatible FFI bindings for geneva-uploader

// Allow #[repr(C)] and other FFI attributes without wrapping in unsafe blocks (standard FFI practice)
#![allow(unsafe_attr_outside_unsafe)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use geneva_uploader::client::{EncodedBatch, GenevaClient, GenevaClientConfig};
use geneva_uploader::AuthMethod;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use std::path::PathBuf;

/// Magic number for handle validation
const GENEVA_HANDLE_MAGIC: u64 = 0xFEED_BEEF;

/// Shared Tokio runtime for async operations
/// TODO: Consider making runtime configurable via FFI in the future:
/// - Thread count configuration (currently uses available_parallelism())
/// - Runtime type selection (multi_thread vs current_thread)
/// - Per-client runtimes vs shared global runtime
/// - External runtime integration (accept user-provided runtime handle)
/// - Runtime lifecycle management for FFI (shutdown, cleanup)
static RUNTIME: OnceLock<Runtime> = OnceLock::new(); // TODO - Consider using LazyLock once msrv is 1.80.

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4),
            )
            .thread_name("geneva-ffi-worker")
            .enable_time()
            .enable_io() // Only enable time + I/O for Geneva's needs
            .build()
            .expect("Failed to create Tokio runtime for Geneva FFI")
    })
}

/// Trait for handles that support validation
trait ValidatedHandle {
    fn magic(&self) -> u64;
    fn set_magic(&mut self, magic: u64);
}

/// Generic validation function that works for any ValidatedHandle
unsafe fn validate_handle<T: ValidatedHandle>(handle: *const T) -> GenevaError {
    if handle.is_null() {
        return GenevaError::NullPointer;
    }

    let handle_ref = unsafe { handle.as_ref().unwrap() };

    if handle_ref.magic() != GENEVA_HANDLE_MAGIC {
        return GenevaError::InvalidHandle;
    }

    GenevaError::Success
}

/// Generic function to clear magic number on free
unsafe fn clear_handle_magic<T: ValidatedHandle>(handle: *mut T) {
    if !handle.is_null() {
        if let Some(h) = unsafe { handle.as_mut() } {
            h.set_magic(0);
        }
    }
}

/// Opaque handle for GenevaClient
pub struct GenevaClientHandle {
    magic: u64, // Magic number for handle validation
    client: GenevaClient,
}

impl ValidatedHandle for GenevaClientHandle {
    fn magic(&self) -> u64 {
        self.magic
    }

    fn set_magic(&mut self, magic: u64) {
        self.magic = magic;
    }
}

/// Opaque handle holding encoded batches
pub struct EncodedBatchesHandle {
    magic: u64,
    batches: Vec<EncodedBatch>,
}

impl ValidatedHandle for EncodedBatchesHandle {
    fn magic(&self) -> u64 {
        self.magic
    }

    fn set_magic(&mut self, magic: u64) {
        self.magic = magic;
    }
}

/// Configuration for certificate auth (valid only when auth_method == 1)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenevaCertAuthConfig {
    pub cert_path: *const c_char,     // Path to certificate file
    pub cert_password: *const c_char, // Certificate password
}

/// Configuration for Workload Identity auth (valid only when auth_method == 2)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenevaWorkloadIdentityAuthConfig {
    pub resource: *const c_char, // Azure AD resource URI (e.g., "https://monitor.azure.com")
}

/// Configuration for User-assigned Managed Identity by client ID (valid only when auth_method == 3)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenevaUserManagedIdentityAuthConfig {
    pub client_id: *const c_char, // Azure AD client ID
}

/// Configuration for User-assigned Managed Identity by object ID (valid only when auth_method == 4)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenevaUserManagedIdentityByObjectIdAuthConfig {
    pub object_id: *const c_char, // Azure AD object ID
}

/// Configuration for User-assigned Managed Identity by resource ID (valid only when auth_method == 5)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenevaUserManagedIdentityByResourceIdAuthConfig {
    pub resource_id: *const c_char, // Azure resource ID
}

#[repr(C)]
pub union GenevaAuthConfig {
    pub cert: GenevaCertAuthConfig, // Valid when auth_method == 1
    pub workload_identity: GenevaWorkloadIdentityAuthConfig, // Valid when auth_method == 2
    pub user_msi: GenevaUserManagedIdentityAuthConfig, // Valid when auth_method == 3
    pub user_msi_objid: GenevaUserManagedIdentityByObjectIdAuthConfig, // Valid when auth_method == 4
    pub user_msi_resid: GenevaUserManagedIdentityByResourceIdAuthConfig, // Valid when auth_method == 5
}

/// Configuration structure for Geneva client (C-compatible, tagged union)
///
/// # Auth Methods
/// - 0 = SystemManagedIdentity (auto-detected VM/AKS system-assigned identity)
/// - 1 = Certificate (mTLS with PKCS#12 certificate)
/// - 2 = WorkloadIdentity (explicit Azure Workload Identity for AKS)
/// - 3 = UserManagedIdentity (by client ID)
/// - 4 = UserManagedIdentityByObjectId (by object ID)
/// - 5 = UserManagedIdentityByResourceId (by resource ID)
///
/// # Resource Configuration
/// Different auth methods require different resource configuration:
/// - **Auth methods 0, 3, 4, 5 (MSI variants)**: Use the `msi_resource` field to specify the Azure AD resource URI
/// - **Auth method 2 (WorkloadIdentity)**: Use `auth.workload_identity.resource` field
/// - **Auth method 1 (Certificate)**: No resource needed
///
/// The `msi_resource` field specifies the Azure AD resource URI for token acquisition
/// (e.g., <https://monitor.azure.com>). For user-assigned identities (3, 4, 5), the
/// auth union specifies WHICH identity to use, while `msi_resource` specifies WHAT
/// Azure resource to request tokens FOR. These are orthogonal concerns.
#[repr(C)]
pub struct GenevaConfig {
    pub endpoint: *const c_char,
    pub environment: *const c_char,
    pub account: *const c_char,
    pub namespace_name: *const c_char,
    pub region: *const c_char,
    pub config_major_version: c_uint,
    pub auth_method: c_uint,
    pub tenant: *const c_char,
    pub role_name: *const c_char,
    pub role_instance: *const c_char,
    pub auth: GenevaAuthConfig, // Active member selected by auth_method
    pub msi_resource: *const c_char, // Azure AD resource URI for MSI auth (auth methods 0, 3, 4, 5). Not used for auth methods 1, 2. Nullable.
}

/// Error codes returned by FFI functions
/// TODO: Use cbindgen to auto-generate geneva_errors.h from this enum to eliminate duplication
#[repr(C)]
#[derive(PartialEq)]
pub enum GenevaError {
    // Base codes (stable)
    Success = 0,
    InvalidConfig = 1,
    InitializationFailed = 2,
    UploadFailed = 3,
    InvalidData = 4,
    InternalError = 5,

    // Granular argument/data errors (used)
    NullPointer = 100,
    EmptyInput = 101,
    DecodeFailed = 102,
    IndexOutOfRange = 103,
    InvalidHandle = 104,

    // Granular config/auth errors (used)
    InvalidAuthMethod = 110,
    InvalidCertConfig = 111,
    InvalidWorkloadIdentityConfig = 112,
    InvalidUserMsiConfig = 113,
    InvalidUserMsiByObjectIdConfig = 114,
    InvalidUserMsiByResourceIdConfig = 115,

    // Missing required config (granular INVALID_CONFIG)
    MissingEndpoint = 130,
    MissingEnvironment = 131,
    MissingAccount = 132,
    MissingNamespace = 133,
    MissingRegion = 134,
    MissingTenant = 135,
    MissingRoleName = 136,
    MissingRoleInstance = 137,
}

/// Safely converts a C string to Rust String
unsafe fn c_str_to_string(ptr: *const c_char, field_name: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("Field '{field_name}' is null"));
    }

    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(format!("Invalid UTF-8 in field '{field_name}'")),
    }
}

/// Writes error message to caller-provided buffer if available
///
/// This function has zero allocation cost when err_msg_out is NULL or err_msg_len is 0.
/// Only allocates (via Display::to_string) when caller requests error details.
unsafe fn write_error_if_provided(
    err_msg_out: *mut c_char,
    err_msg_len: usize,
    error: &impl std::fmt::Display,
) {
    if !err_msg_out.is_null() && err_msg_len > 0 {
        let error_string = error.to_string();
        let bytes_to_copy = error_string.len().min(err_msg_len - 1);
        if bytes_to_copy > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    error_string.as_ptr() as *const c_char,
                    err_msg_out,
                    bytes_to_copy,
                );
            }
        }
        // Always null-terminate if we have space
        unsafe {
            *err_msg_out.add(bytes_to_copy) = 0;
        }
    }
}

/// Creates a new Geneva client with explicit result semantics (no TLS needed).
///
/// On success: returns GenevaError::Success and writes a non-null handle into *out_handle.
/// On failure: returns an error code and writes a diagnostic message into err_msg_out if provided.
///
/// # Safety
/// - config must be a valid pointer to a GenevaConfig struct
/// - out_handle must be a valid pointer to receive the client handle
/// - err_msg_out: optional buffer to receive error message (can be NULL)
/// - err_msg_len: size of err_msg_out buffer
/// - caller must eventually call geneva_client_free on the returned handle
#[no_mangle]
pub unsafe extern "C" fn geneva_client_new(
    config: *const GenevaConfig,
    out_handle: *mut *mut GenevaClientHandle,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    // Validate pointers
    if config.is_null() || out_handle.is_null() {
        return GenevaError::NullPointer;
    }
    unsafe { *out_handle = ptr::null_mut() };

    let config = unsafe { config.as_ref().unwrap() };

    // Validate required fields with granular error codes
    if config.endpoint.is_null() {
        return GenevaError::MissingEndpoint;
    }
    if config.environment.is_null() {
        return GenevaError::MissingEnvironment;
    }
    if config.account.is_null() {
        return GenevaError::MissingAccount;
    }
    if config.namespace_name.is_null() {
        return GenevaError::MissingNamespace;
    }
    if config.region.is_null() {
        return GenevaError::MissingRegion;
    }
    if config.tenant.is_null() {
        return GenevaError::MissingTenant;
    }
    if config.role_name.is_null() {
        return GenevaError::MissingRoleName;
    }
    if config.role_instance.is_null() {
        return GenevaError::MissingRoleInstance;
    }

    // Convert C strings to Rust strings
    let endpoint = match unsafe { c_str_to_string(config.endpoint, "endpoint") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let environment = match unsafe { c_str_to_string(config.environment, "environment") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let account = match unsafe { c_str_to_string(config.account, "account") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let namespace = match unsafe { c_str_to_string(config.namespace_name, "namespace_name") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let region = match unsafe { c_str_to_string(config.region, "region") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let tenant = match unsafe { c_str_to_string(config.tenant, "tenant") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let role_name = match unsafe { c_str_to_string(config.role_name, "role_name") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };
    let role_instance = match unsafe { c_str_to_string(config.role_instance, "role_instance") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidConfig;
        }
    };

    // Auth method conversion
    let auth_method = match config.auth_method {
        0 => {
            // System-assigned Managed Identity
            AuthMethod::SystemManagedIdentity
        }

        1 => {
            // Certificate authentication: read fields from tagged union
            let cert = unsafe { config.auth.cert };
            if cert.cert_path.is_null() {
                return GenevaError::InvalidCertConfig;
            }
            if cert.cert_password.is_null() {
                return GenevaError::InvalidCertConfig;
            }
            let cert_path = match unsafe { c_str_to_string(cert.cert_path, "cert_path") } {
                Ok(s) => PathBuf::from(s),
                Err(e) => {
                    unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                    return GenevaError::InvalidConfig;
                }
            };
            let cert_password =
                match unsafe { c_str_to_string(cert.cert_password, "cert_password") } {
                    Ok(s) => s,
                    Err(e) => {
                        unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                        return GenevaError::InvalidConfig;
                    }
                };
            AuthMethod::Certificate {
                path: cert_path,
                password: cert_password,
            }
        }

        2 => {
            // Workload Identity authentication
            let workload_identity = unsafe { config.auth.workload_identity };
            if workload_identity.resource.is_null() {
                return GenevaError::InvalidWorkloadIdentityConfig;
            }
            let resource = match unsafe { c_str_to_string(workload_identity.resource, "resource") }
            {
                Ok(s) => s,
                Err(e) => {
                    unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                    return GenevaError::InvalidConfig;
                }
            };
            AuthMethod::WorkloadIdentity { resource }
        }

        3 => {
            // User-assigned Managed Identity by client ID
            let user_msi = unsafe { config.auth.user_msi };
            if user_msi.client_id.is_null() {
                return GenevaError::InvalidUserMsiConfig;
            }
            let client_id = match unsafe { c_str_to_string(user_msi.client_id, "client_id") } {
                Ok(s) => s,
                Err(e) => {
                    unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                    return GenevaError::InvalidConfig;
                }
            };
            AuthMethod::UserManagedIdentity { client_id }
        }

        4 => {
            // User-assigned Managed Identity by object ID
            let user_msi_objid = unsafe { config.auth.user_msi_objid };
            if user_msi_objid.object_id.is_null() {
                return GenevaError::InvalidUserMsiByObjectIdConfig;
            }
            let object_id = match unsafe { c_str_to_string(user_msi_objid.object_id, "object_id") }
            {
                Ok(s) => s,
                Err(e) => {
                    unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                    return GenevaError::InvalidConfig;
                }
            };
            AuthMethod::UserManagedIdentityByObjectId { object_id }
        }

        5 => {
            // User-assigned Managed Identity by resource ID
            let user_msi_resid = unsafe { config.auth.user_msi_resid };
            if user_msi_resid.resource_id.is_null() {
                return GenevaError::InvalidUserMsiByResourceIdConfig;
            }
            let resource_id =
                match unsafe { c_str_to_string(user_msi_resid.resource_id, "resource_id") } {
                    Ok(s) => s,
                    Err(e) => {
                        unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                        return GenevaError::InvalidConfig;
                    }
                };
            AuthMethod::UserManagedIdentityByResourceId { resource_id }
        }

        _ => {
            return GenevaError::InvalidAuthMethod;
        }
    };

    // Parse optional MSI resource
    let msi_resource = if !config.msi_resource.is_null() {
        match unsafe { c_str_to_string(config.msi_resource, "msi_resource") } {
            Ok(s) => Some(s),
            Err(e) => {
                unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                return GenevaError::InvalidConfig;
            }
        }
    } else {
        None
    };

    // Build client config
    let geneva_config = GenevaClientConfig {
        endpoint,
        environment,
        account,
        namespace,
        region,
        config_major_version: config.config_major_version,
        auth_method,
        tenant,
        role_name,
        role_instance,
        msi_resource,
    };

    // Create client
    let client = match GenevaClient::new(geneva_config) {
        Ok(client) => client,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InitializationFailed;
        }
    };

    let handle = GenevaClientHandle {
        magic: GENEVA_HANDLE_MAGIC,
        client,
    };
    unsafe { *out_handle = Box::into_raw(Box::new(handle)) };
    GenevaError::Success
}

/// Encode and compress logs into batches (synchronous)
///
/// # Safety
/// - handle must be a valid pointer returned by geneva_client_new
/// - data must be a valid pointer to protobuf-encoded ExportLogsServiceRequest
/// - data_len must be the correct length of the data
/// - out_batches must be non-null; on success it receives a non-null pointer the caller must free with geneva_batches_free
/// - err_msg_out: optional buffer to receive error message (can be NULL)
/// - err_msg_len: size of err_msg_out buffer
#[no_mangle]
pub unsafe extern "C" fn geneva_encode_and_compress_logs(
    handle: *mut GenevaClientHandle,
    data: *const u8,
    data_len: usize,
    out_batches: *mut *mut EncodedBatchesHandle,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    if out_batches.is_null() {
        return GenevaError::NullPointer;
    }
    unsafe { *out_batches = ptr::null_mut() };

    if handle.is_null() {
        return GenevaError::NullPointer;
    }
    if data.is_null() {
        return GenevaError::NullPointer;
    }
    if data_len == 0 {
        return GenevaError::EmptyInput;
    }

    // Validate handle first
    let validation_result = unsafe { validate_handle(handle) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }

    let handle_ref = unsafe { handle.as_ref().unwrap() };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

    let logs_data: ExportLogsServiceRequest = match Message::decode(data_slice) {
        Ok(data) => data,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::DecodeFailed;
        }
    };

    let resource_logs = logs_data.resource_logs;
    match handle_ref.client.encode_and_compress_logs(&resource_logs) {
        Ok(batches) => {
            let h = EncodedBatchesHandle {
                magic: GENEVA_HANDLE_MAGIC,
                batches,
            };
            unsafe { *out_batches = Box::into_raw(Box::new(h)) };
            GenevaError::Success
        }
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            GenevaError::InternalError
        }
    }
}

/// Encode and compress spans into batches (synchronous)
///
/// # Safety
/// - handle must be a valid pointer returned by geneva_client_new
/// - data must be a valid pointer to protobuf-encoded ExportTraceServiceRequest
/// - data_len must be the correct length of the data
/// - out_batches must be non-null; on success it receives a non-null pointer the caller must free with geneva_batches_free
/// - err_msg_out: optional buffer to receive error message (can be NULL)
/// - err_msg_len: size of err_msg_out buffer
#[no_mangle]
pub unsafe extern "C" fn geneva_encode_and_compress_spans(
    handle: *mut GenevaClientHandle,
    data: *const u8,
    data_len: usize,
    out_batches: *mut *mut EncodedBatchesHandle,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    if out_batches.is_null() {
        return GenevaError::NullPointer;
    }
    unsafe { *out_batches = ptr::null_mut() };

    if handle.is_null() {
        return GenevaError::NullPointer;
    }
    if data.is_null() {
        return GenevaError::NullPointer;
    }
    if data_len == 0 {
        return GenevaError::EmptyInput;
    }

    // Validate handle first
    let validation_result = unsafe { validate_handle(handle) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }

    let handle_ref = unsafe { handle.as_ref().unwrap() };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

    let spans_data: ExportTraceServiceRequest = match Message::decode(data_slice) {
        Ok(data) => data,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::DecodeFailed;
        }
    };

    let resource_spans = spans_data.resource_spans;
    match handle_ref.client.encode_and_compress_spans(&resource_spans) {
        Ok(batches) => {
            let h = EncodedBatchesHandle {
                magic: GENEVA_HANDLE_MAGIC,
                batches,
            };
            unsafe { *out_batches = Box::into_raw(Box::new(h)) };
            GenevaError::Success
        }
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            GenevaError::InternalError
        }
    }
}

// ---------- Row writer batch encoding (Bond-free caller interface) ----------
//
// PERFORMANCE NOTE: Each geneva_row_write_* call crosses the FFI boundary.
// For high-throughput scenarios (>100K records/sec), enable Link-Time Optimization
// (LTO) when statically linking the Rust library into your C/C++ application.
// With LTO, the compiler can inline these calls across the language boundary,
// eliminating the indirect call overhead entirely.
//
// Without LTO, each call is an indirect function call (~2-5ns). For a batch of
// 10,000 records × 20 fields = 200,000 calls ≈ 0.4-1ms, which is typically
// negligible compared to LZ4 compression and HTTP upload time.

/// Field definition for the row writer schema.
/// The caller declares these once to define the column layout.
#[repr(C)]
pub struct GenevaFieldDef {
    /// Field name, UTF-8, null-terminated. Must remain valid until `geneva_batch_finish`.
    pub name: *const c_char,
    /// Field type. The library maps this internally to the appropriate encoding.
    pub field_type: GenevaFieldType,
}

/// Logical type tags for field values.
/// These are NOT Bond types — the library maps them internally.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GenevaFieldType {
    /// UTF-8 string
    String = 0,
    /// 32-bit signed integer
    Int32 = 1,
    /// 64-bit signed integer
    Int64 = 2,
    /// 32-bit unsigned integer
    Uint32 = 3,
    /// 64-bit floating point
    Double = 4,
    /// Boolean (0 = false, nonzero = true)
    Bool = 5,
}

/// Opaque batch builder handle. Accumulates rows streamed via `geneva_row_write_*`,
/// then produces compressed `EncodedBatch`es on `geneva_batch_finish`.
pub struct GenevaBatchBuilderHandle {
    magic: u64,
    /// Cached FieldDef vec (built once in `begin`)
    field_defs: Vec<geneva_uploader::FieldDef>,
    /// Expected field types in order (for validation)
    field_types: Vec<GenevaFieldType>,
    /// Event name shared by all rows
    event_name: String,
    /// Severity level shared by all rows
    level: u8,
    /// Accumulated rows
    rows: Vec<geneva_uploader::RawRow>,
    /// Current row being built (in-progress Bond bytes)
    current_row: Vec<u8>,
    /// Timestamp for the current row
    current_timestamp_ns: u64,
    /// Number of fields written to the current row (for validation)
    current_field_index: usize,
}

impl ValidatedHandle for GenevaBatchBuilderHandle {
    fn magic(&self) -> u64 {
        self.magic
    }
    fn set_magic(&mut self, magic: u64) {
        self.magic = magic;
    }
}

/// Begin building a batch with a fixed schema.
///
/// All rows added to this builder must provide field values in the same order
/// as the `fields` array, using the corresponding `geneva_row_write_*` function
/// for each field's declared type.
///
/// # Safety
/// - `handle` must be a valid pointer returned by `geneva_client_new`
/// - `fields[0..field_count-1]` must be valid `GenevaFieldDef` entries
/// - `event_name` must be a valid null-terminated UTF-8 string
/// - Field name pointers must remain valid until `geneva_batch_finish` or
///   `geneva_batch_builder_free` is called
/// - `out_builder` must be non-null
#[no_mangle]
pub unsafe extern "C" fn geneva_batch_begin(
    handle: *mut GenevaClientHandle,
    fields: *const GenevaFieldDef,
    field_count: usize,
    event_name: *const c_char,
    level: u8,
    out_builder: *mut *mut GenevaBatchBuilderHandle,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    if out_builder.is_null() {
        return GenevaError::NullPointer;
    }
    unsafe { *out_builder = ptr::null_mut() };

    if handle.is_null() || fields.is_null() || event_name.is_null() {
        return GenevaError::NullPointer;
    }
    if field_count == 0 {
        return GenevaError::EmptyInput;
    }

    let validation_result = unsafe { validate_handle(handle) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }

    let event_name_str = match unsafe { CStr::from_ptr(event_name) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            return GenevaError::InvalidData;
        }
    };

    let field_slice = unsafe { std::slice::from_raw_parts(fields, field_count) };

    let mut field_defs = Vec::with_capacity(field_count);
    let mut field_types = Vec::with_capacity(field_count);

    for (i, f) in field_slice.iter().enumerate() {
        if f.name.is_null() {
            unsafe {
                write_error_if_provided(
                    err_msg_out,
                    err_msg_len,
                    &format!("field {i} has null name"),
                )
            };
            return GenevaError::NullPointer;
        }
        let name_str = match unsafe { CStr::from_ptr(f.name) }.to_str() {
            Ok(s) => s,
            Err(e) => {
                unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
                return GenevaError::InvalidData;
            }
        };

        let bond_type = match f.field_type {
            GenevaFieldType::String => geneva_uploader::BondDataType::BT_STRING,
            GenevaFieldType::Int32 => geneva_uploader::BondDataType::BT_INT32,
            GenevaFieldType::Int64 => geneva_uploader::BondDataType::BT_INT64,
            GenevaFieldType::Uint32 => geneva_uploader::BondDataType::BT_UINT32,
            GenevaFieldType::Double => geneva_uploader::BondDataType::BT_DOUBLE,
            GenevaFieldType::Bool => geneva_uploader::BondDataType::BT_BOOL,
        };

        field_defs.push(geneva_uploader::FieldDef {
            name: std::borrow::Cow::Owned(name_str.to_string()),
            field_id: (i + 1) as u16,
            type_id: bond_type,
        });
        field_types.push(f.field_type);
    }

    let builder = GenevaBatchBuilderHandle {
        magic: GENEVA_HANDLE_MAGIC,
        field_defs,
        field_types,
        event_name: event_name_str.to_string(),
        level,
        rows: Vec::new(),
        current_row: Vec::new(),
        current_timestamp_ns: 0,
        current_field_index: 0,
    };

    unsafe { *out_builder = Box::into_raw(Box::new(builder)) };
    GenevaError::Success
}

/// Begin a new row within the batch.
///
/// Must be called before writing field values for each record.
/// If a previous row was in progress, it is automatically finalized.
///
/// # Safety
/// - `builder` must be a valid pointer returned by `geneva_batch_begin`
#[no_mangle]
pub unsafe extern "C" fn geneva_row_begin(
    builder: *mut GenevaBatchBuilderHandle,
    timestamp_ns: u64,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let validation_result = unsafe { validate_handle(builder as *const _) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }

    let b = unsafe { builder.as_mut().unwrap() };

    // Finalize previous row if one was in progress
    if b.current_field_index > 0 {
        if b.current_field_index != b.field_defs.len() {
            return GenevaError::InvalidData; // incomplete previous row
        }
        let row = geneva_uploader::RawRow {
            timestamp_ns: b.current_timestamp_ns,
            row_data: std::mem::take(&mut b.current_row),
        };
        b.rows.push(row);
    }

    b.current_row.clear();
    b.current_row.reserve(b.field_defs.len() * 50);
    b.current_timestamp_ns = timestamp_ns;
    b.current_field_index = 0;

    GenevaError::Success
}

/// Write a UTF-8 string field value.
/// Must be called for the next field in schema order and that field must be of type String.
///
/// # Safety
/// - `builder` must be valid
/// - `ptr` must point to `len` bytes of valid UTF-8 (or be null with len=0 for empty string)
/// - The pointed-to data must remain valid only for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_string(
    builder: *mut GenevaBatchBuilderHandle,
    ptr: *const u8,
    len: usize,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::String {
        return GenevaError::InvalidData;
    }

    if ptr.is_null() || len == 0 {
        geneva_uploader::BondWriter::write_string(&mut b.current_row, "");
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => geneva_uploader::BondWriter::write_string(&mut b.current_row, s),
            Err(_) => return GenevaError::InvalidData,
        }
    }

    b.current_field_index += 1;
    GenevaError::Success
}

/// Write a 32-bit signed integer field value.
///
/// # Safety
/// - `builder` must be valid
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_int32(
    builder: *mut GenevaBatchBuilderHandle,
    value: i32,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::Int32 {
        return GenevaError::InvalidData;
    }

    geneva_uploader::BondWriter::write_numeric(&mut b.current_row, value);
    b.current_field_index += 1;
    GenevaError::Success
}

/// Write a 64-bit signed integer field value.
///
/// # Safety
/// - `builder` must be valid
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_int64(
    builder: *mut GenevaBatchBuilderHandle,
    value: i64,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::Int64 {
        return GenevaError::InvalidData;
    }

    geneva_uploader::BondWriter::write_numeric(&mut b.current_row, value);
    b.current_field_index += 1;
    GenevaError::Success
}

/// Write a 32-bit unsigned integer field value.
///
/// # Safety
/// - `builder` must be valid
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_uint32(
    builder: *mut GenevaBatchBuilderHandle,
    value: u32,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::Uint32 {
        return GenevaError::InvalidData;
    }

    geneva_uploader::BondWriter::write_numeric(&mut b.current_row, value);
    b.current_field_index += 1;
    GenevaError::Success
}

/// Write a 64-bit floating point field value.
///
/// # Safety
/// - `builder` must be valid
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_double(
    builder: *mut GenevaBatchBuilderHandle,
    value: f64,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::Double {
        return GenevaError::InvalidData;
    }

    geneva_uploader::BondWriter::write_numeric(&mut b.current_row, value);
    b.current_field_index += 1;
    GenevaError::Success
}

/// Write a boolean field value.
///
/// # Safety
/// - `builder` must be valid
#[no_mangle]
pub unsafe extern "C" fn geneva_row_write_bool(
    builder: *mut GenevaBatchBuilderHandle,
    value: u8,
) -> GenevaError {
    if builder.is_null() {
        return GenevaError::NullPointer;
    }
    let b = unsafe { builder.as_mut().unwrap() };

    if b.current_field_index >= b.field_types.len() {
        return GenevaError::IndexOutOfRange;
    }
    if b.field_types[b.current_field_index] != GenevaFieldType::Bool {
        return GenevaError::InvalidData;
    }

    geneva_uploader::BondWriter::write_bool(&mut b.current_row, value != 0);
    b.current_field_index += 1;
    GenevaError::Success
}

/// Finish the batch: finalize the last row, assemble the CentralBlob,
/// compress with LZ4, and return encoded batches.
///
/// The builder is consumed and freed by this call (do NOT call
/// `geneva_batch_builder_free` afterwards).
///
/// # Safety
/// - `handle` must be a valid `GenevaClientHandle`
/// - `builder` must be a valid pointer returned by `geneva_batch_begin`
/// - `out_batches` must be non-null
#[no_mangle]
pub unsafe extern "C" fn geneva_batch_finish(
    handle: *mut GenevaClientHandle,
    builder: *mut GenevaBatchBuilderHandle,
    out_batches: *mut *mut EncodedBatchesHandle,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    if out_batches.is_null() {
        return GenevaError::NullPointer;
    }
    unsafe { *out_batches = ptr::null_mut() };

    if handle.is_null() || builder.is_null() {
        return GenevaError::NullPointer;
    }

    // Validate both handles
    let validation_result = unsafe { validate_handle(handle) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }
    let validation_result = unsafe { validate_handle(builder as *const _) };
    if validation_result != GenevaError::Success {
        return validation_result;
    }

    let handle_ref = unsafe { handle.as_ref().unwrap() };

    // Take ownership of builder (it will be freed at the end of this function)
    unsafe { clear_handle_magic(builder) };
    let mut b = unsafe { *Box::from_raw(builder) };

    // Finalize last row if in progress
    if !b.current_row.is_empty() {
        if b.current_field_index != b.field_defs.len() {
            let msg = format!(
                "incomplete final row: expected {} fields, got {}",
                b.field_defs.len(),
                b.current_field_index
            );
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &msg) };
            return GenevaError::InvalidData;
        }
        let row = geneva_uploader::RawRow {
            timestamp_ns: b.current_timestamp_ns,
            row_data: std::mem::take(&mut b.current_row),
        };
        b.rows.push(row);
    }

    if b.rows.is_empty() {
        return GenevaError::EmptyInput;
    }

    // Delegate to library for schema assembly, blob construction, and compression
    match handle_ref
        .client
        .encode_raw_batch(&b.field_defs, &b.event_name, b.level, &b.rows)
    {
        Ok(batches) => {
            let h = EncodedBatchesHandle {
                magic: GENEVA_HANDLE_MAGIC,
                batches,
            };
            unsafe { *out_batches = Box::into_raw(Box::new(h)) };
            GenevaError::Success
        }
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            GenevaError::InternalError
        }
    }
}

/// Free a batch builder without finishing it (discard accumulated data).
///
/// Safe to call with NULL (no-op). Do NOT call after `geneva_batch_finish`
/// (which already frees the builder).
///
/// # Safety
/// - `builder` must be a valid pointer from `geneva_batch_begin`, or null
#[no_mangle]
pub unsafe extern "C" fn geneva_batch_builder_free(builder: *mut GenevaBatchBuilderHandle) {
    if !builder.is_null() {
        unsafe { clear_handle_magic(builder) };
        let _ = unsafe { Box::from_raw(builder) };
    }
}

/// Returns the number of batches in the encoded batches handle
///
/// # Safety
/// - batches must be a valid pointer returned by geneva_encode_and_compress_logs, or null
#[no_mangle]
pub unsafe extern "C" fn geneva_batches_len(batches: *const EncodedBatchesHandle) -> usize {
    // Validate batches
    match unsafe { validate_handle(batches) } {
        GenevaError::Success => {
            // Safe to dereference after validation
            let batches_ref = unsafe { batches.as_ref().unwrap() };
            batches_ref.batches.len()
        }
        _ => 0, // Return 0 for invalid handles
    }
}

/// Uploads a specific batch synchronously
///
/// # Safety
/// - handle must be a valid pointer returned by geneva_client_new
/// - batches must be a valid pointer returned by geneva_encode_and_compress_logs
/// - index must be less than the value returned by geneva_batches_len
/// - err_msg_out: optional buffer to receive error message (can be NULL)
/// - err_msg_len: size of err_msg_out buffer
#[no_mangle]
pub unsafe extern "C" fn geneva_upload_batch_sync(
    handle: *mut GenevaClientHandle,
    batches: *const EncodedBatchesHandle,
    index: usize,
    err_msg_out: *mut c_char,
    err_msg_len: usize,
) -> GenevaError {
    // Validate client handle
    match unsafe { validate_handle(handle) } {
        GenevaError::Success => {}
        error => return error,
    }
    // validate batches
    match unsafe { validate_handle(batches) } {
        GenevaError::Success => {}
        error => return error,
    }

    // Now we know both handles are valid, safe to dereference
    let handle_ref = unsafe { handle.as_ref().unwrap() };
    let batches_ref = unsafe { batches.as_ref().unwrap() };

    if index >= batches_ref.batches.len() {
        return GenevaError::IndexOutOfRange;
    }

    let batch = &batches_ref.batches[index];
    let client = &handle_ref.client;
    let res = runtime().block_on(async move { client.upload_batch(batch).await });
    match res {
        Ok(_) => GenevaError::Success,
        Err(e) => {
            unsafe { write_error_if_provided(err_msg_out, err_msg_len, &e) };
            GenevaError::UploadFailed
        }
    }
}

/// Frees encoded batches handle
///
/// # Safety
/// - batches must be a valid pointer returned by geneva_encode_and_compress_logs, or null
/// - batches must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn geneva_batches_free(batches: *mut EncodedBatchesHandle) {
    if !batches.is_null() {
        unsafe { clear_handle_magic(batches) };
        let _ = unsafe { Box::from_raw(batches) };
    }
}

// Frees a Geneva client handle
///
/// # Safety
/// - client handle must be a valid pointer returned by geneva_client_new
/// - client handle must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn geneva_client_free(handle: *mut GenevaClientHandle) {
    if !handle.is_null() {
        unsafe { clear_handle_magic(handle) };
        let _ = unsafe { Box::from_raw(handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // Build a minimal unsigned JWT with the Endpoint claim and an exp. Matches what extract_endpoint_from_token expects.
    #[allow(dead_code)]
    fn generate_mock_jwt_and_expiry(endpoint: &str, ttl_secs: i64) -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use chrono::{Duration, Utc};

        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let exp = Utc::now() + Duration::seconds(ttl_secs);
        let payload = format!(r#"{{"Endpoint":"{endpoint}","exp":{}}}"#, exp.timestamp());

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let token = format!("{}.{}.{sig}", header_b64, payload_b64, sig = "dummy");

        (token, exp.to_rfc3339())
    }

    #[test]
    fn test_geneva_client_new_with_null_config() {
        unsafe {
            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(std::ptr::null(), &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::NullPointer as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_upload_batch_sync_with_nulls() {
        unsafe {
            let result =
                geneva_upload_batch_sync(ptr::null_mut(), ptr::null(), 0, ptr::null_mut(), 0);
            assert_eq!(result as u32, GenevaError::NullPointer as u32);
        }
    }

    #[test]
    fn test_encode_with_nulls() {
        unsafe {
            let mut out: *mut EncodedBatchesHandle = std::ptr::null_mut();
            let rc = geneva_encode_and_compress_logs(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut out,
                ptr::null_mut(),
                0,
            );
            assert_eq!(rc as u32, GenevaError::NullPointer as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_geneva_client_free_with_null() {
        unsafe {
            // Should not crash
            geneva_client_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_null_field_validation() {
        unsafe {
            // Test with missing endpoint
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: ptr::null(), // Missing endpoint should cause failure
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 0, // SystemManagedIdentity - union not used
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                // SAFETY: GenevaAuthConfig only contains raw pointers (*const c_char).
                // Zero-initializing raw pointers creates null pointers, which is valid.
                // The union is never accessed for SystemManagedIdentity (auth_method 0).
                auth: std::mem::zeroed(),
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::MissingEndpoint as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_invalid_auth_method() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 99, // Invalid auth method - union not used
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: std::mem::zeroed(), // Union not accessed for invalid auth method
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::InvalidAuthMethod as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_certificate_auth_missing_cert_path() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 1, // Certificate auth
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    cert: GenevaCertAuthConfig {
                        cert_path: ptr::null(),
                        cert_password: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::InvalidCertConfig as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_workload_identity_auth_missing_resource() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 2, // Workload Identity
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    workload_identity: GenevaWorkloadIdentityAuthConfig {
                        resource: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::InvalidWorkloadIdentityConfig as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_user_msi_auth_missing_client_id() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 3, // User Managed Identity by client ID
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    user_msi: GenevaUserManagedIdentityAuthConfig {
                        client_id: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::InvalidUserMsiConfig as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_user_msi_auth_by_object_id_missing() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 4, // User Managed Identity by object ID
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    user_msi_objid: GenevaUserManagedIdentityByObjectIdAuthConfig {
                        object_id: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(
                rc as u32,
                GenevaError::InvalidUserMsiByObjectIdConfig as u32
            );
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_user_msi_auth_by_resource_id_missing() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 5, // User Managed Identity by resource ID
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    user_msi_resid: GenevaUserManagedIdentityByResourceIdAuthConfig {
                        resource_id: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(
                rc as u32,
                GenevaError::InvalidUserMsiByResourceIdConfig as u32
            );
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_certificate_auth_missing_cert_password() {
        unsafe {
            let endpoint = CString::new("https://test.geneva.com").unwrap();
            let environment = CString::new("test").unwrap();
            let account = CString::new("testaccount").unwrap();
            let namespace = CString::new("testns").unwrap();
            let region = CString::new("testregion").unwrap();
            let tenant = CString::new("testtenant").unwrap();
            let role_name = CString::new("testrole").unwrap();
            let role_instance = CString::new("testinstance").unwrap();
            let cert_path = CString::new("/path/to/cert.p12").unwrap();

            let config = GenevaConfig {
                endpoint: endpoint.as_ptr(),
                environment: environment.as_ptr(),
                account: account.as_ptr(),
                namespace_name: namespace.as_ptr(),
                region: region.as_ptr(),
                config_major_version: 1,
                auth_method: 1, // Certificate auth
                tenant: tenant.as_ptr(),
                role_name: role_name.as_ptr(),
                role_instance: role_instance.as_ptr(),
                auth: GenevaAuthConfig {
                    cert: GenevaCertAuthConfig {
                        cert_path: cert_path.as_ptr(),
                        cert_password: ptr::null(),
                    },
                },
                msi_resource: ptr::null(),
            };

            let mut out: *mut GenevaClientHandle = std::ptr::null_mut();
            let rc = geneva_client_new(&config, &mut out, ptr::null_mut(), 0);
            assert_eq!(rc as u32, GenevaError::InvalidCertConfig as u32);
            assert!(out.is_null());
        }
    }

    #[test]
    fn test_batches_len_with_null() {
        unsafe {
            let n = geneva_batches_len(ptr::null());
            assert_eq!(n, 0, "batches_len should return 0 for null pointer");
        }
    }

    #[test]
    fn test_batches_free_with_null() {
        unsafe {
            geneva_batches_free(ptr::null_mut());
        }
    }

    // Integration-style test: encode via FFI then upload via FFI using MockAuth + Wiremock server.
    // Uses otlp_builder to construct an ExportLogsServiceRequest payload.
    #[test]
    #[cfg(feature = "mock_auth")]
    fn test_encode_and_upload_with_mock_server() {
        use otlp_builder::builder::build_otlp_logs_minimal;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Start mock server on the shared runtime used by the FFI code
        let mock_server = runtime().block_on(async { MockServer::start().await });
        let ingestion_endpoint = mock_server.uri();

        // Build JWT dynamically so the Endpoint claim matches the mock server, and compute a fresh expiry
        let (auth_token, auth_token_expiry) =
            generate_mock_jwt_and_expiry(&ingestion_endpoint, 24 * 3600);

        // Mock config service (GET)
        runtime().block_on(async {
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{
                        "IngestionGatewayInfo": {{
                            "Endpoint": "{ingestion_endpoint}",
                            "AuthToken": "{auth_token}",
                            "AuthTokenExpiryTime": "{auth_token_expiry}"
                        }},
                        "StorageAccountKeys": [{{
                            "AccountMonikerName": "testdiagaccount",
                            "AccountGroupName": "testgroup",
                            "IsPrimaryMoniker": true
                        }}],
                        "TagId": "test"
                    }}"#
                )))
                .mount(&mock_server)
                .await;

            // Mock ingestion service (POST)
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(202).set_body_string(r#"{"ticket":"accepted"}"#),
                )
                .mount(&mock_server)
                .await;
        });

        // Build a real GenevaClient using MockAuth (no mTLS), then wrap it in the FFI handle.
        let cfg = GenevaClientConfig {
            endpoint: mock_server.uri(),
            environment: "test".to_string(),
            account: "test".to_string(),
            namespace: "testns".to_string(),
            region: "testregion".to_string(),
            config_major_version: 1,
            auth_method: AuthMethod::MockAuth,
            tenant: "testtenant".to_string(),
            role_name: "testrole".to_string(),
            role_instance: "testinstance".to_string(),
            msi_resource: None,
        };
        let client = GenevaClient::new(cfg).expect("failed to create GenevaClient with MockAuth");

        // Wrap into an FFI-compatible handle
        let handle = GenevaClientHandle {
            magic: GENEVA_HANDLE_MAGIC,
            client,
        };
        // Keep the boxed handle alive until we explicitly free it via FFI
        let mut handle_box = Box::new(handle);
        let handle_ptr: *mut GenevaClientHandle = &mut *handle_box;

        // Build minimal OTLP logs payload bytes using the test helper
        let bytes = build_otlp_logs_minimal("TestEvent", "hello-world", Some(("rk", "rv")));

        // Encode via FFI
        let mut batches_ptr: *mut EncodedBatchesHandle = std::ptr::null_mut();
        let rc = unsafe {
            geneva_encode_and_compress_logs(
                handle_ptr,
                bytes.as_ptr(),
                bytes.len(),
                &mut batches_ptr,
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc as u32, GenevaError::Success as u32, "encode failed");
        assert!(
            !batches_ptr.is_null(),
            "out_batches should be non-null on success"
        );

        // Validate number of batches and upload first batch via FFI (sync)
        let len = unsafe { geneva_batches_len(batches_ptr) };
        assert!(len >= 1, "expected at least one encoded batch");

        // Attempt upload (ignore return code; we will assert via recorded requests)
        let _ = unsafe {
            geneva_upload_batch_sync(handle_ptr, batches_ptr as *const _, 0, ptr::null_mut(), 0)
        };

        // Cleanup: free batches and client
        unsafe {
            geneva_batches_free(batches_ptr);
        }
        // Transfer ownership of handle_box to the FFI free function
        let raw_handle = Box::into_raw(handle_box);
        unsafe {
            geneva_client_free(raw_handle);
        }

        // Keep mock_server in scope until end of test
        drop(mock_server);
    }

    // Verifies batching groups by LogRecord.event_name:
    // multiple different event_names in one request produce multiple batches,
    // and each batch upload hits ingestion with the corresponding event query param.
    #[test]
    #[cfg(feature = "mock_auth")]
    fn test_encode_batching_by_event_name_and_upload() {
        use wiremock::http::Method;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Start mock server
        let mock_server = runtime().block_on(async { MockServer::start().await });
        let ingestion_endpoint = mock_server.uri();
        let (auth_token, auth_token_expiry) =
            generate_mock_jwt_and_expiry(&ingestion_endpoint, 24 * 3600);

        // Mock Geneva Config (GET) and Ingestion (POST)
        runtime().block_on(async {
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{
                        "IngestionGatewayInfo": {{
                            "Endpoint": "{ingestion_endpoint}",
                            "AuthToken": "{auth_token}",
                            "AuthTokenExpiryTime": "{auth_token_expiry}"
                        }},
                        "StorageAccountKeys": [{{
                            "AccountMonikerName": "testdiagaccount",
                            "AccountGroupName": "testgroup",
                            "IsPrimaryMoniker": true
                        }}],
                        "TagId": "test"
                    }}"#
                )))
                .mount(&mock_server)
                .await;

            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(202).set_body_string(r#"{"ticket":"accepted"}"#),
                )
                .mount(&mock_server)
                .await;
        });

        // Build client with MockAuth
        let cfg = GenevaClientConfig {
            endpoint: mock_server.uri(),
            environment: "test".to_string(),
            account: "test".to_string(),
            namespace: "testns".to_string(),
            region: "testregion".to_string(),
            config_major_version: 1,
            auth_method: AuthMethod::MockAuth,
            tenant: "testtenant".to_string(),
            role_name: "testrole".to_string(),
            role_instance: "testinstance".to_string(),
            msi_resource: None,
        };
        let client = GenevaClient::new(cfg).expect("failed to create GenevaClient with MockAuth");

        // Wrap client into FFI handle
        let mut handle_box = Box::new(GenevaClientHandle {
            magic: GENEVA_HANDLE_MAGIC,
            client,
        });
        let handle_ptr: *mut GenevaClientHandle = &mut *handle_box;

        // Build ExportLogsServiceRequest with two different event_names
        let log1 = opentelemetry_proto::tonic::logs::v1::LogRecord {
            observed_time_unix_nano: 1_700_000_000_000_000_001,
            event_name: "EventA".to_string(),
            severity_number: 9,
            ..Default::default()
        };
        let log2 = opentelemetry_proto::tonic::logs::v1::LogRecord {
            observed_time_unix_nano: 1_700_000_000_000_000_002,
            event_name: "EventB".to_string(),
            severity_number: 10,
            ..Default::default()
        };
        let scope_logs = opentelemetry_proto::tonic::logs::v1::ScopeLogs {
            log_records: vec![log1, log2],
            ..Default::default()
        };
        let resource_logs = opentelemetry_proto::tonic::logs::v1::ResourceLogs {
            scope_logs: vec![scope_logs],
            ..Default::default()
        };
        let req = ExportLogsServiceRequest {
            resource_logs: vec![resource_logs],
        };
        let bytes = req.encode_to_vec();

        // Encode via FFI
        let mut batches_ptr: *mut EncodedBatchesHandle = std::ptr::null_mut();
        let rc = unsafe {
            geneva_encode_and_compress_logs(
                handle_ptr,
                bytes.as_ptr(),
                bytes.len(),
                &mut batches_ptr,
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc as u32, GenevaError::Success as u32, "encode failed");
        assert!(!batches_ptr.is_null());

        // Expect 2 batches (EventA, EventB)
        let len = unsafe { geneva_batches_len(batches_ptr) };
        assert_eq!(len, 2, "expected 2 batches grouped by event_name");

        // Upload all batches
        for i in 0..len {
            let _ = unsafe {
                geneva_upload_batch_sync(handle_ptr, batches_ptr as *const _, i, ptr::null_mut(), 0)
            };
        }

        // Verify requests contain event=EventA and event=EventB in their URLs
        // Poll until both POSTs appear or timeout to avoid flakiness
        let (urls, has_a, has_b) = runtime().block_on(async {
            use tokio::time::{sleep, Duration};
            let mut last_urls: Vec<String> = Vec::new();
            for _ in 0..200 {
                let reqs = mock_server.received_requests().await.unwrap();
                let posts: Vec<String> = reqs
                    .iter()
                    .filter(|r| r.method == Method::Post)
                    .map(|r| r.url.to_string())
                    .collect();

                let has_a = posts.iter().any(|u| u.contains("event=EventA"));
                let has_b = posts.iter().any(|u| u.contains("event=EventB"));
                if has_a && has_b {
                    return (posts, true, true);
                }

                if !posts.is_empty() {
                    last_urls = posts.clone();
                }

                sleep(Duration::from_millis(20)).await;
            }

            if last_urls.is_empty() {
                let reqs = mock_server.received_requests().await.unwrap();
                last_urls = reqs.into_iter().map(|r| r.url.to_string()).collect();
            }
            let has_a = last_urls.iter().any(|u| u.contains("event=EventA"));
            let has_b = last_urls.iter().any(|u| u.contains("event=EventB"));
            (last_urls, has_a, has_b)
        });
        assert!(
            has_a,
            "Expected request containing event=EventA; got: {urls:?}"
        );
        assert!(
            has_b,
            "Expected request containing event=EventB; got: {urls:?}"
        );

        // Cleanup
        unsafe { geneva_batches_free(batches_ptr) };
        let raw_handle = Box::into_raw(handle_box);
        unsafe { geneva_client_free(raw_handle) };
        drop(mock_server);
    }
}
