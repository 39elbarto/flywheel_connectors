//! S3 API types.

use serde::{Deserialize, Serialize};

/// S3 object metadata returned from list and head operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object key
    pub key: String,
    /// Object size in bytes
    pub size: u64,
    /// Last modified timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// ETag (entity tag)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Storage class
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

/// S3 bucket info returned from list buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    /// Bucket name
    pub name: String,
    /// Creation date (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

/// Response from put_object / copy_object operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectResponse {
    /// ETag of the uploaded/copied object
    pub etag: String,
}

/// Response from get_object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetObjectResponse {
    /// Object body as a string (base64-encoded for binary content)
    pub body: String,
    /// Content type of the object
    pub content_type: String,
}

/// Response from head_object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadObjectResponse {
    /// Content type
    pub content_type: String,
    /// Content length in bytes
    pub content_length: u64,
    /// ETag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Last modified timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// Response from list_objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    /// List of objects
    pub contents: Vec<ObjectInfo>,
    /// Whether results are truncated
    pub is_truncated: bool,
}

/// Response from list_buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListBucketsResponse {
    /// List of buckets
    pub buckets: Vec<BucketInfo>,
}

/// Response from generate_presigned_url.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedUrlResponse {
    /// The presigned URL
    pub url: String,
}

/// S3 API error structure returned from the service.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Error code (e.g., "NoSuchKey", "NoSuchBucket")
    #[serde(alias = "Code")]
    pub code: String,
    /// Error message
    #[serde(alias = "Message")]
    pub message: String,
}
