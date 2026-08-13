//! Strict codec for one inherited host-egress Unix stream.
//!
//! This module owns framing and wire-contract validation only. The host binary
//! supplies the request handler and remains responsible for authorization,
//! provider egress, and lifecycle ordering. A session is intentionally
//! sequential: read one request, handle it, write one response, then read the
//! next request.

use std::fmt;

use fcp_async_core::io::{AsyncReadExt, AsyncWriteExt};
use fcp_async_core::net::UnixStream;
use fcp_manifest::{
    HOST_EGRESS_WIRE_MAX_FRAME_BYTES, HOST_EGRESS_WIRE_SCHEMA_VERSION, HostEgressWireError,
    HostEgressWireRequest, HostEgressWireRequestPayload, HostEgressWireResponse,
    HostEgressWireResponseBody, HostEgressWireRoute,
};
use subtle::ConstantTimeEq;

/// Authentication and framing errors are deliberately content-free.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum InheritedEgressCodecError {
    #[error("inherited host-egress stream is unavailable")]
    Io,
    #[error("inherited host-egress frame is truncated")]
    Truncated,
    #[error("inherited host-egress frame is oversized")]
    Oversized,
    #[error("inherited host-egress frame is empty")]
    EmptyFrame,
    #[error("inherited host-egress frame is not valid UTF-8")]
    InvalidUtf8,
    #[error("inherited host-egress frame is not valid JSON")]
    InvalidJson,
    #[error("inherited host-egress schema version is unsupported")]
    WrongSchema,
    #[error("inherited host-egress authentication failed")]
    WrongAuth,
    #[error("inherited host-egress route and payload disagree")]
    WrongRoutePayload,
    #[error("inherited host-egress request id is invalid")]
    WrongRequestId,
    #[error("inherited host-egress response is invalid")]
    InvalidResponse,
    #[error("inherited host-egress authentication token is invalid")]
    InvalidAuthToken,
    #[error("inherited host-egress response has no matching request")]
    MissingRequest,
}

/// A single authenticated, sequential inherited-channel session.
pub struct InheritedEgressCodec {
    stream: UnixStream,
    auth_token: Vec<u8>,
    retained_read_buffer: Vec<u8>,
    next_request_id: u64,
    pending_response: Option<(u64, HostEgressWireRoute)>,
}

impl fmt::Debug for InheritedEgressCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InheritedEgressCodec")
            .field("auth_token", &"[redacted]")
            .field(
                "retained_read_buffer_bytes",
                &self.retained_read_buffer.len(),
            )
            .field("next_request_id", &self.next_request_id)
            .field("pending_response", &self.pending_response)
            .finish()
    }
}

impl InheritedEgressCodec {
    /// Create a codec over one already-connected host/connector Unix stream.
    ///
    /// The token is copied into private memory and never appears in Debug or
    /// error values. The stream must already have been claimed and validated by
    /// the narrow sandbox inherited-FD primitive.
    pub fn new(stream: UnixStream, auth_token: &str) -> Result<Self, InheritedEgressCodecError> {
        if auth_token.is_empty() || !auth_token.is_ascii() {
            return Err(InheritedEgressCodecError::InvalidAuthToken);
        }
        Ok(Self {
            stream,
            auth_token: auth_token.as_bytes().to_vec(),
            retained_read_buffer: Vec::new(),
            next_request_id: 1,
            pending_response: None,
        })
    }

    /// Read, authenticate, and validate exactly one request frame.
    ///
    /// If the underlying read returns multiple newline-delimited frames, only
    /// the first is returned and the remainder is retained for the next call.
    /// The caller should handle and respond before reading the next request.
    pub async fn read_request(
        &mut self,
    ) -> Result<HostEgressWireRequest, InheritedEgressCodecError> {
        if self.pending_response.is_some() {
            return Err(InheritedEgressCodecError::MissingRequest);
        }
        let frame = self.read_frame().await?;
        let request = decode_request(&frame)?;
        validate_request(&request, &self.auth_token, self.next_request_id)?;
        self.pending_response = Some((request.request_id, request.route));
        self.next_request_id = self.next_request_id.saturating_add(1);
        Ok(request)
    }

    /// Validate and write exactly one response for the last request.
    pub async fn write_response(
        &mut self,
        response: &HostEgressWireResponse,
    ) -> Result<(), InheritedEgressCodecError> {
        let (request_id, request_route) = self
            .pending_response
            .take()
            .ok_or(InheritedEgressCodecError::MissingRequest)?;
        if let Err(error) = validate_response(response, request_id, request_route) {
            self.pending_response = Some((request_id, request_route));
            return Err(error);
        }
        let frame = encode_response(response)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|_| InheritedEgressCodecError::Io)
    }

    /// Build a typed success response for the current request.
    pub fn success_response(
        &self,
        body: HostEgressWireResponseBody,
    ) -> Result<HostEgressWireResponse, InheritedEgressCodecError> {
        let (request_id, route) = self
            .pending_response
            .ok_or(InheritedEgressCodecError::MissingRequest)?;
        Ok(HostEgressWireResponse {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id,
            route,
            status: 200,
            body: Some(body),
            error: None,
        })
    }

    /// Build a typed failure response for the current request.
    pub fn error_response(
        &self,
        status: u16,
        error: HostEgressWireError,
    ) -> Result<HostEgressWireResponse, InheritedEgressCodecError> {
        let (request_id, route) = self
            .pending_response
            .ok_or(InheritedEgressCodecError::MissingRequest)?;
        Ok(HostEgressWireResponse {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id,
            route,
            status,
            body: None,
            error: Some(error),
        })
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>, InheritedEgressCodecError> {
        loop {
            if let Some(newline) = self
                .retained_read_buffer
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let frame_len = newline.saturating_add(1);
                if frame_len > HOST_EGRESS_WIRE_MAX_FRAME_BYTES {
                    return Err(InheritedEgressCodecError::Oversized);
                }
                if newline == 0 {
                    return Err(InheritedEgressCodecError::EmptyFrame);
                }
                let mut frame = self
                    .retained_read_buffer
                    .drain(..frame_len)
                    .collect::<Vec<_>>();
                frame.pop();
                return Ok(frame);
            }
            if self.retained_read_buffer.len() >= HOST_EGRESS_WIRE_MAX_FRAME_BYTES {
                return Err(InheritedEgressCodecError::Oversized);
            }
            let remaining =
                HOST_EGRESS_WIRE_MAX_FRAME_BYTES.saturating_sub(self.retained_read_buffer.len());
            let mut chunk = [0_u8; 1024];
            let read_len = remaining.min(chunk.len());
            let count = self
                .stream
                .read(&mut chunk[..read_len])
                .await
                .map_err(|_| InheritedEgressCodecError::Io)?;
            if count == 0 {
                return Err(if self.retained_read_buffer.is_empty() {
                    InheritedEgressCodecError::Io
                } else {
                    InheritedEgressCodecError::Truncated
                });
            }
            self.retained_read_buffer.extend_from_slice(&chunk[..count]);
        }
    }
}

fn decode_request(frame: &[u8]) -> Result<HostEgressWireRequest, InheritedEgressCodecError> {
    std::str::from_utf8(frame).map_err(|_| InheritedEgressCodecError::InvalidUtf8)?;
    serde_json::from_slice(frame).map_err(|_| InheritedEgressCodecError::InvalidJson)
}

fn encode_response(
    response: &HostEgressWireResponse,
) -> Result<Vec<u8>, InheritedEgressCodecError> {
    let mut frame =
        serde_json::to_vec(response).map_err(|_| InheritedEgressCodecError::InvalidResponse)?;
    if frame.is_empty() || frame.len().saturating_add(1) > HOST_EGRESS_WIRE_MAX_FRAME_BYTES {
        return Err(InheritedEgressCodecError::Oversized);
    }
    if frame.contains(&b'\n') {
        return Err(InheritedEgressCodecError::InvalidResponse);
    }
    frame.push(b'\n');
    Ok(frame)
}

fn validate_request(
    request: &HostEgressWireRequest,
    auth_token: &[u8],
    expected_request_id: u64,
) -> Result<(), InheritedEgressCodecError> {
    if request.schema_version != HOST_EGRESS_WIRE_SCHEMA_VERSION {
        return Err(InheritedEgressCodecError::WrongSchema);
    }
    if !bool::from(request.auth_token.as_bytes().ct_eq(auth_token)) {
        return Err(InheritedEgressCodecError::WrongAuth);
    }
    if request.request_id != expected_request_id {
        return Err(InheritedEgressCodecError::WrongRequestId);
    }
    if !route_matches_payload(request.route, &request.payload) {
        return Err(InheritedEgressCodecError::WrongRoutePayload);
    }
    Ok(())
}

fn route_matches_payload(
    route: HostEgressWireRoute,
    payload: &HostEgressWireRequestPayload,
) -> bool {
    matches!(
        (route, payload),
        (
            HostEgressWireRoute::Http,
            HostEgressWireRequestPayload::Http(_)
        ) | (
            HostEgressWireRoute::Tcp,
            HostEgressWireRequestPayload::Tcp(_)
        )
    )
}

fn validate_response(
    response: &HostEgressWireResponse,
    expected_request_id: u64,
    expected_route: HostEgressWireRoute,
) -> Result<(), InheritedEgressCodecError> {
    if response.schema_version != HOST_EGRESS_WIRE_SCHEMA_VERSION
        || response.request_id != expected_request_id
        || response.route != expected_route
    {
        return Err(InheritedEgressCodecError::InvalidResponse);
    }
    if !(100..=599).contains(&response.status) {
        return Err(InheritedEgressCodecError::InvalidResponse);
    }
    if (200..=299).contains(&response.status) {
        let body_matches = matches!(
            (&response.route, response.body.as_ref()),
            (
                HostEgressWireRoute::Http,
                Some(HostEgressWireResponseBody::Http(_)),
            ) | (
                HostEgressWireRoute::Tcp,
                Some(HostEgressWireResponseBody::Tcp(_)),
            )
        );
        if response.error.is_some() || !body_matches {
            return Err(InheritedEgressCodecError::InvalidResponse);
        }
    } else if response.body.is_some() || response.error.is_none() {
        return Err(InheritedEgressCodecError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_manifest::{
        Base64Bytes, HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpResponse,
        HostEgressTcpResponse,
    };

    fn context() -> fcp_manifest::HostEgressContext {
        HostEgressContext {
            connector_id: "fcp.test".to_owned(),
            operation_id: "test.read".to_owned(),
            resource_uri: "fwc-test://local".to_owned(),
            zone_id: "z:test".to_owned(),
            request_id: "req-1".to_owned(),
            correlation_id: None,
            capability_token_cbor_b64: "base64:test".to_owned(),
        }
    }

    fn metadata() -> HostEgressDecisionMetadata {
        HostEgressDecisionMetadata {
            connector_id: "fcp.test".to_owned(),
            operation_id: "test.read".to_owned(),
            zone_id: "z:test".to_owned(),
            request_id: "req-1".to_owned(),
            correlation_id: None,
            execution_mode: "host_proxy".to_owned(),
            constraint_source: "test".to_owned(),
            decision: "allow".to_owned(),
            resolved_host: "example.test".to_owned(),
            resolved_port: 443,
            credential_injected: false,
            elapsed_ms: 1,
        }
    }

    fn http_request(id: u64, token: &str) -> HostEgressWireRequest {
        HostEgressWireRequest {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id: id,
            auth_token: token.to_owned(),
            route: HostEgressWireRoute::Http,
            payload: HostEgressWireRequestPayload::Http(fcp_manifest::HostEgressHttpRequest {
                context: context(),
                url: "https://example.test/read".to_owned(),
                method: "GET".to_owned(),
                headers: Vec::new(),
                body: None,
                credential_id: None,
            }),
        }
    }

    fn tcp_request(id: u64, token: &str) -> HostEgressWireRequest {
        HostEgressWireRequest {
            schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
            request_id: id,
            auth_token: token.to_owned(),
            route: HostEgressWireRoute::Tcp,
            payload: HostEgressWireRequestPayload::Tcp(fcp_manifest::HostEgressTcpRequest {
                context: context(),
                host: "example.test".to_owned(),
                port: 443,
                tls: true,
                sni_override: None,
                write: None,
                read_limit_bytes: Some(16),
                credential_id: None,
            }),
        }
    }

    fn response_body(route: HostEgressWireRoute) -> HostEgressWireResponseBody {
        match route {
            HostEgressWireRoute::Http => HostEgressWireResponseBody::Http(HostEgressHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Base64Bytes::from_vec(Vec::new()),
                egress: metadata(),
            }),
            HostEgressWireRoute::Tcp => HostEgressWireResponseBody::Tcp(HostEgressTcpResponse {
                bytes_written: 0,
                bytes_read: 0,
                read: Base64Bytes::from_vec(Vec::new()),
                egress: metadata(),
            }),
        }
    }

    #[test]
    fn http_and_tcp_round_trip_contracts_validate() {
        for (request, route) in [
            (http_request(1, "secret"), HostEgressWireRoute::Http),
            (tcp_request(1, "secret"), HostEgressWireRoute::Tcp),
        ] {
            let frame = serde_json::to_vec(&request).expect("request JSON");
            let decoded = decode_request(&frame).expect("request decode");
            validate_request(&decoded, b"secret", 1).expect("request validation");
            let response = HostEgressWireResponse {
                schema_version: HOST_EGRESS_WIRE_SCHEMA_VERSION,
                request_id: 1,
                route,
                status: 200,
                body: Some(response_body(route)),
                error: None,
            };
            validate_response(&response, 1, route).expect("response validation");
            assert!(
                !encode_response(&response)
                    .expect("response encoding")
                    .is_empty()
            );
        }
    }

    #[test]
    fn wrong_auth_schema_and_route_payload_are_rejected() {
        let request = http_request(1, "secret");
        assert_eq!(
            validate_request(&request, b"other", 1),
            Err(InheritedEgressCodecError::WrongAuth)
        );

        let mut wrong_schema = request.clone();
        wrong_schema.schema_version = HOST_EGRESS_WIRE_SCHEMA_VERSION.saturating_add(1);
        assert_eq!(
            validate_request(&wrong_schema, b"secret", 1),
            Err(InheritedEgressCodecError::WrongSchema)
        );

        let wrong_route = HostEgressWireRequest {
            route: HostEgressWireRoute::Tcp,
            ..request
        };
        assert_eq!(
            validate_request(&wrong_route, b"secret", 1),
            Err(InheritedEgressCodecError::WrongRoutePayload)
        );
    }

    #[test]
    fn malformed_oversized_truncated_and_pipelined_frames_are_strict() {
        assert_eq!(
            decode_request(b"{not-json}"),
            Err(InheritedEgressCodecError::InvalidJson)
        );
        assert_eq!(
            decode_request(&[0xff]),
            Err(InheritedEgressCodecError::InvalidUtf8)
        );

        let mut codec = test_codec();
        codec.retained_read_buffer = b"a\nb\n".to_vec();
        let first = fcp_async_core::runtime::block_on_sync(codec.read_frame())
            .expect("runtime")
            .expect("first pipelined frame");
        assert_eq!(first, b"a");
        assert_eq!(codec.retained_read_buffer, b"b\n");

        codec.retained_read_buffer = vec![b'x'; HOST_EGRESS_WIRE_MAX_FRAME_BYTES];
        let oversized =
            fcp_async_core::runtime::block_on_sync(codec.read_frame()).expect("runtime");
        assert_eq!(oversized, Err(InheritedEgressCodecError::Oversized));

        let (mut peer, stream) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut codec = InheritedEgressCodec::new(
            UnixStream::from_std(stream).expect("async stream"),
            "top-secret",
        )
        .expect("codec");
        std::io::Write::write_all(&mut peer, b"partial").expect("partial frame");
        drop(peer);
        let truncated =
            fcp_async_core::runtime::block_on_sync(codec.read_frame()).expect("runtime");
        assert_eq!(truncated, Err(InheritedEgressCodecError::Truncated));
    }

    #[test]
    fn debug_and_errors_redact_auth_and_payload() {
        let request = http_request(1, "top-secret");
        let debug = format!("{request:?}");
        assert!(!debug.contains("top-secret"));
        assert!(!debug.contains("example.test/read"));
        let codec = test_codec();
        let debug = format!("{codec:?}");
        assert!(!debug.contains("top-secret"));
        assert!(!format!("{}", InheritedEgressCodecError::WrongAuth).contains("top-secret"));
    }

    #[cfg(target_os = "linux")]
    fn test_codec() -> InheritedEgressCodec {
        let (_peer, stream) = std::os::unix::net::UnixStream::pair().expect("pair");
        let stream = UnixStream::from_std(stream).expect("async stream");
        InheritedEgressCodec::new(stream, "top-secret").expect("codec")
    }
}
