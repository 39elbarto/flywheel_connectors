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

/// Response from create_bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBucketResponse {
    /// Bucket name
    pub bucket: String,
    /// Whether the bucket was created
    pub created: bool,
}

/// Response from delete_bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteBucketResponse {
    /// Bucket name
    pub bucket: String,
    /// Whether the bucket was deleted
    pub deleted: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_info_skip_none() {
        let obj = ObjectInfo {
            key: "photos/cat.jpg".into(),
            size: 2048,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        assert!(!json_str.contains("last_modified"));
        assert!(!json_str.contains("etag"));
        assert!(!json_str.contains("storage_class"));
    }

    #[test]
    fn object_info_full() {
        let obj = ObjectInfo {
            key: "data.csv".into(),
            size: 1_000_000,
            last_modified: Some("2026-03-01T00:00:00Z".into()),
            etag: Some("\"abc123\"".into()),
            storage_class: Some("STANDARD".into()),
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        let back: ObjectInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.size, 1_000_000);
        assert_eq!(back.storage_class.as_deref(), Some("STANDARD"));
    }

    #[test]
    fn bucket_info_serde() {
        let b = BucketInfo {
            name: "my-bucket".into(),
            creation_date: Some("2026-01-01T00:00:00Z".into()),
        };
        let json_str = serde_json::to_string(&b).unwrap();
        let back: BucketInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "my-bucket");
    }

    #[test]
    fn put_object_response_serde() {
        let resp = PutObjectResponse { etag: "\"def456\"".into() };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PutObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.etag, "\"def456\"");
    }

    #[test]
    fn get_object_response_serde() {
        let resp = GetObjectResponse {
            body: "base64data".into(),
            content_type: "application/json".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: GetObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.content_type, "application/json");
    }

    #[test]
    fn head_object_response_skip_none() {
        let resp = HeadObjectResponse {
            content_type: "text/plain".into(),
            content_length: 512,
            etag: None,
            last_modified: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("etag"));
        assert!(!json_str.contains("last_modified"));
    }

    #[test]
    fn list_objects_response_serde() {
        let resp = ListObjectsResponse {
            contents: vec![ObjectInfo {
                key: "file.txt".into(),
                size: 100,
                last_modified: None,
                etag: None,
                storage_class: None,
            }],
            is_truncated: false,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: ListObjectsResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.contents.len(), 1);
        assert!(!back.is_truncated);
    }

    #[test]
    fn list_buckets_response_serde() {
        let json = json!({"buckets": [{"name": "b1"}, {"name": "b2"}]});
        let resp: ListBucketsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.buckets.len(), 2);
    }

    #[test]
    fn create_bucket_response_serde() {
        let resp = CreateBucketResponse { bucket: "new-bucket".into(), created: true };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: CreateBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.created);
    }

    #[test]
    fn delete_bucket_response_serde() {
        let resp = DeleteBucketResponse { bucket: "old-bucket".into(), deleted: true };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: DeleteBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn presigned_url_response_serde() {
        let resp = PresignedUrlResponse { url: "https://s3.example.com/signed".into() };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PresignedUrlResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.url.starts_with("https://"));
    }

    #[test]
    fn api_error_lowercase() {
        let json = json!({"code": "NoSuchKey", "message": "Key not found"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "NoSuchKey");
    }

    #[test]
    fn api_error_uppercase_alias() {
        let json = json!({"Code": "NoSuchBucket", "Message": "Bucket not found"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "NoSuchBucket");
        assert_eq!(err.message, "Bucket not found");
    }
}
