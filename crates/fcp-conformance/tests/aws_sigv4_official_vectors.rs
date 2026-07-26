//! Differential `SigV4` harness against AWS's published signing test suite.
//!
//! br-3wt77. The workspace has two independent `SigV4` signers —
//! `fcp_sdk::sigv4` and `fcp_provider_auth` — and until now neither was
//! checked against AWS's own vectors. Each pinned exactly one real vector
//! (`GetBucketLifecycle`), whose path is `/`: the single path for which a correct
//! canonical-URI implementation and a broken one agree. That is precisely why
//! the canonical-URI defect behind br-1nqg7 / br-0lsi3 survived in both crates
//! while every test passed.
//!
//! Vectors are vendored verbatim under `tests/vectors/aws-sigv4/`; see the
//! README there for provenance. They are never fetched at test time.
//!
//! Each case is asserted stage by stage — canonical request, then
//! string-to-sign, then signature — because every `SigV4` stage hashes into the
//! next. Comparing only the final signature would say *that* a signer diverged
//! but never *where*, and the whole value of these fixtures is that they ship
//! the intermediates.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fcp_sdk::sigv4::{
    AwsCredentials, CanonicalPathEncoding, CanonicalPathNormalization, SigV4Signer,
    SignableRequest, SigningScope,
};

/// One vendored case.
struct Vector {
    name: String,
    request: ParsedRequest,
    context: Context,
    expected_canonical_request: String,
    expected_string_to_sign: String,
    expected_signature: String,
}

struct Context {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    region: String,
    service: String,
    timestamp: String,
    /// When true the case expects `x-amz-content-sha256` in the signed set.
    sign_body: bool,
    /// AWS couples two behaviours to this flag: path normalisation (RFC 3986
    /// dot-segment removal) and double-encoding. `normalize: false` is the S3
    /// profile; `true` is every other service.
    normalize: bool,
}

struct ParsedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/aws-sigv4")
}

/// Parse the suite's `request.txt`: an HTTP/1.1 request line, then headers as
/// `Name:value` (no space after the colon), then a blank line, then the body.
///
/// Continuation lines (a header value folded across lines) appear in
/// `get-header-value-multiline` and are joined per RFC 7230 obsolete folding.
fn parse_request(raw: &str) -> ParsedRequest {
    let mut lines = raw.split('\n');
    let request_line = lines.next().unwrap_or_default().trim_end_matches('\r');
    // The target may itself contain a literal space (`get-space-*`), so split
    // on the FIRST and LAST space rather than tokenising: `GET /a b/ HTTP/1.1`.
    let (method, rest) = request_line.split_once(' ').unwrap_or((request_line, ""));
    let method = method.to_string();
    let target = rest
        .rsplit_once(' ')
        .map_or_else(|| rest.to_string(), |(t, _version)| t.to_string());

    let (path, query_str) = target.split_once('?').map_or_else(
        || (target.clone(), String::new()),
        |(p, q)| (p.to_string(), q.to_string()),
    );

    let mut query = BTreeMap::new();
    if !query_str.is_empty() {
        for pair in query_str.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query.insert(decode(k), decode(v));
        }
    }

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    let mut body_lines: Vec<String> = Vec::new();
    let mut in_body = false;

    for line in lines {
        let line = line.trim_end_matches('\r');
        if in_body {
            body_lines.push(line.to_string());
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding (RFC 7230 §3.2.4). AWS replaces the fold
            // with a single SPACE, not a comma — comma-joining is the rule for
            // a REPEATED header name, which is a different case. Measured
            // against get-header-value-multiline, whose expected canonical
            // request is `my-header1:value1 value2 value3`.
            if let Some(key) = &last_key {
                let existing = headers.get(key).cloned().unwrap_or_default();
                headers.insert(key.clone(), format!("{existing} {}", line.trim()));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let key = name.trim().to_lowercase();
            // A repeated header name is comma-joined, per the canonical-request
            // rules the `get-header-key-duplicate` case exercises.
            headers
                .entry(key.clone())
                .and_modify(|existing| {
                    *existing = format!("{existing},{}", value.trim());
                })
                .or_insert_with(|| value.trim().to_string());
            last_key = Some(key);
        }
    }

    ParsedRequest {
        method,
        path,
        query,
        headers,
        body: body_lines.join("\n").into_bytes(),
    }
}

fn decode(s: &str) -> String {
    percent_decode(s)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_context(raw: &str) -> Context {
    let v: serde_json::Value = serde_json::from_str(raw).expect("context.json");
    let creds = &v["credentials"];
    Context {
        access_key_id: creds["access_key_id"].as_str().unwrap_or_default().into(),
        secret_access_key: creds["secret_access_key"]
            .as_str()
            .unwrap_or_default()
            .into(),
        token: creds
            .get("token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        region: v["region"].as_str().unwrap_or_default().into(),
        service: v["service"].as_str().unwrap_or_default().into(),
        timestamp: v["timestamp"].as_str().unwrap_or_default().into(),
        sign_body: v["sign_body"].as_bool().unwrap_or(false),
        normalize: v["normalize"].as_bool().unwrap_or(true),
    }
}

fn load_vectors() -> Vec<Vector> {
    let dir = vectors_dir();
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);

    for entry in entries {
        let p = entry.path();
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let read = |f: &str| {
            std::fs::read_to_string(p.join(f)).unwrap_or_else(|e| panic!("{name}/{f}: {e}"))
        };
        out.push(Vector {
            request: parse_request(&read("request.txt")),
            context: parse_context(&read("context.json")),
            expected_canonical_request: read("header-canonical-request.txt"),
            expected_string_to_sign: read("header-string-to-sign.txt"),
            expected_signature: read("header-signature.txt").trim().to_string(),
            name,
        });
    }
    assert!(!out.is_empty(), "no vendored vectors found");
    out
}

/// The suite's fixtures are the authority on what a correct signer emits. This
/// checks the *parser* first, on a case whose shape is hand-verifiable, so a
/// parser bug cannot silently weaken every downstream assertion.
#[test]
fn request_parser_matches_a_hand_checked_case() {
    let dir = vectors_dir().join("get-vanilla-query-order-key-case");
    let parsed = parse_request(&std::fs::read_to_string(dir.join("request.txt")).unwrap());
    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.path, "/");
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("example.amazonaws.com")
    );
    assert!(parsed.body.is_empty());

    let ctx = parse_context(&std::fs::read_to_string(dir.join("context.json")).unwrap());
    assert_eq!(ctx.access_key_id, "AKIDEXAMPLE");
    assert_eq!(ctx.region, "us-east-1");
    assert_eq!(ctx.service, "service");
    assert_eq!(ctx.timestamp, "2015-08-30T12:36:00Z");

    let multiline = parse_request(
        &std::fs::read_to_string(vectors_dir().join("get-header-value-multiline/request.txt"))
            .unwrap(),
    );
    assert!(
        multiline
            .headers
            .get("my-header1")
            .is_some_and(|v| v == "value1 value2 value3"),
        "folded header values must be space-joined per RFC 7230 unfolding, got {:?}",
        multiline.headers.get("my-header1")
    );
}

/// The suite's `normalize` flag is the S3-vs-everything-else profile selector:
/// `false` means "do not normalise the path, single-encode" (S3), `true` means
/// "normalise and double-encode" (all other services). Every vendored case uses
/// service `service`, i.e. the double-encoding profile, so this pins that the
/// corpus is not silently exercising only one side of the split.
#[test]
fn vendored_corpus_covers_both_normalization_profiles() {
    let vectors = load_vectors();
    let normalized = vectors.iter().filter(|v| v.context.normalize).count();
    let unnormalized = vectors.len() - normalized;
    eprintln!("vectors: {normalized} normalize=true, {unnormalized} normalize=false");
    assert!(normalized > 0, "corpus lost its normalize=true cases");
    assert!(
        unnormalized > 0,
        "corpus lost its normalize=false cases — the S3-side path profile would be untested"
    );
}

fn sign_with_sdk(v: &Vector) -> (String, String, String) {
    let ts = chrono::DateTime::parse_from_rfc3339(&v.context.timestamp)
        .expect("timestamp")
        .with_timezone(&chrono::Utc);

    let creds = AwsCredentials {
        access_key_id: v.context.access_key_id.clone(),
        secret_access_key: v.context.secret_access_key.clone(),
        session_token: v.context.token.clone(),
    };
    let scope = SigningScope {
        region: v.context.region.clone(),
        service: v.context.service.clone(),
    };
    // AWS's vectors sign a service that does not carry x-amz-content-sha256, so
    // the signer is driven in exactly that shape. Leaving the header on would
    // make every case mismatch for a reason unrelated to the canonical-URI and
    // query-encoding rules these fixtures exist to pin. Verified by measurement:
    // with the header enabled, the sole difference on get-header-key-duplicate
    // was that one header line — every other byte, including the duplicate-key
    // comma join, already matched.
    let signer = SigV4Signer::new(creds, scope)
        .with_fixed_time(ts)
        .with_content_sha256_header(v.context.sign_body)
        // Every vendored case uses service `service`, so the scope-derived
        // profile would normalise all 38. The corpus instead carries the profile
        // per case in `context.normalize`, which is the axis these fixtures
        // exist to exercise, so it is driven explicitly here.
        .with_path_normalization(if v.context.normalize {
            CanonicalPathNormalization::RemoveDotSegments
        } else {
            CanonicalPathNormalization::Preserve
        });

    let req = SignableRequest {
        method: v.request.method.clone(),
        uri: v.request.path.clone(),
        query_params: v.request.query.clone(),
        headers: v.request.headers.clone(),
        payload_hash: SignableRequest::hash_payload(&v.request.body),
    };
    let (_, trace) = signer.sign_traced(&req);
    (
        trace.canonical_request,
        trace.string_to_sign,
        trace.signature,
    )
}

/// Cases where `fcp-sdk` does not yet reproduce AWS's canonical request.
///
/// This list is a RATCHET, not a suppression: the test asserts the divergent
/// set is EXACTLY this, so a new divergence fails, and fixing one also fails
/// until the name is removed here. Each entry is categorised, and the
/// categories are tracked on the follow-up bead rather than left as folklore.
///
/// A. Path normalisation not implemented (6). AWS removes RFC 3986 dot
///    segments and collapses duplicate slashes before encoding for services in
///    the normalising profile; `canonical_uri_path` decodes and re-encodes but
///    never normalises. `/example/..` signs as `/example/..`, AWS signs `/`.
/// B. One encoding pass too many for these paths (3). We emit `%2520` and
///    `%25E1%2588%25B4` where the suite expects `%20` and `%E1%88%B4` — exactly
///    one extra pass. Leading hypothesis: the whole aws-c-auth v4 corpus is
///    generated with double-URI-encoding DISABLED, which would make these
///    vectors describe the S3 path profile even though `service` reads
///    `service`. That is a harness-mapping question, NOT licence to change the
///    encoding contract: that contract was settled by measurement against live
///    AWS in br-1nqg7 / br-0lsi3 and must not be re-derived from these files.
///    Note the other 26 cases cannot discriminate — their paths contain nothing
///    that needs escaping, so one pass and two agree.
/// C. Canonical query ordering (1). AWS orders query parameters by their
///    ENCODED key bytes; `build_canonical_query` receives a `BTreeMap` already
///    keyed by decoded values, so `%E1%88%B4` sorts last for us and first for
///    AWS.
/// D. Header-value whitespace (1). AWS collapses sequential internal spaces in
///    unquoted header values; we only trim the ends, so `"a   b   c"` stays
///    wide where AWS expects `"a b c"`.
/// E. Session token always signed (1). `post-sts-header-after` adds the token
///    after signing and expects it absent from the signed set; we sign
///    `x-amz-security-token` whenever the credentials carry one. Its sibling
///    `post-sts-header-before` passes.
const KNOWN_DIVERGENT: &[&str] = &[
    // B — encoding passes
    "get-space-normalized",
    "get-space-unnormalized",
    "get-utf8",
    // C — canonical query ordering
    "get-vanilla-query-order-encoded",
    // E — session token always signed
    "post-sts-header-after",
];

/// Every case is checked stage by stage. Divergences are reported all at once,
/// per stage, because a signer bug shows up as a FAMILY of related failures and
/// the family is the diagnosis.
#[test]
fn sdk_signer_against_official_vectors() {
    let vectors = load_vectors();
    let mut diverged: Vec<String> = Vec::new();
    let mut stage_detail: Vec<String> = Vec::new();

    for v in &vectors {
        let (canonical, sts, sig) = sign_with_sdk(v);
        let canonical_ok = canonical.trim_end() == v.expected_canonical_request.trim_end();
        let sts_ok = sts.trim_end() == v.expected_string_to_sign.trim_end();
        let sig_ok = sig == v.expected_signature;

        if canonical_ok && sts_ok && sig_ok {
            continue;
        }
        diverged.push(v.name.clone());

        // A canonical-request match with a downstream mismatch would mean the
        // hashing or key-derivation stage is broken, which is a different and
        // much more serious class than a canonicalisation difference.
        assert!(
            !(canonical_ok && (!sts_ok || !sig_ok)),
            "{}: canonical request matches AWS but a later stage does not — \
             string_to_sign_ok={sts_ok} signature_ok={sig_ok}. That implicates \
             hashing or signing-key derivation, not canonicalisation.",
            v.name
        );
        stage_detail.push(format!("{} (canonical request)", v.name));
    }

    diverged.sort();
    let mut expected: Vec<String> = KNOWN_DIVERGENT.iter().map(|s| (*s).to_string()).collect();
    expected.sort();

    let matched = vectors.len() - diverged.len();
    eprintln!(
        "aws-sigv4 official vectors: {matched}/{} cases reproduce AWS exactly at all three \
         stages; {} known divergences",
        vectors.len(),
        diverged.len()
    );
    if !stage_detail.is_empty() {
        eprintln!("divergent stages: {stage_detail:?}");
    }

    let newly_broken: Vec<_> = diverged.iter().filter(|n| !expected.contains(n)).collect();
    let newly_fixed: Vec<_> = expected.iter().filter(|n| !diverged.contains(n)).collect();

    assert!(
        newly_broken.is_empty(),
        "NEW SigV4 divergence from AWS's published vectors: {newly_broken:?}. \
         This is a regression — the signer changed behaviour on a case that used to match."
    );
    assert!(
        newly_fixed.is_empty(),
        "These cases now match AWS: {newly_fixed:?}. Remove them from KNOWN_DIVERGENT \
         so the ratchet holds them from here on."
    );
}

/// Guards the thing the single-vector era could not: that the corpus actually
/// exercises paths where a canonical-URI bug is observable. 26 of the 38 cases
/// have paths needing no escaping and would pass under a broken encoder too.
#[test]
fn corpus_contains_paths_that_discriminate_canonical_uri_bugs() {
    let vectors = load_vectors();
    let discriminating = vectors
        .iter()
        .filter(|v| {
            v.request.path.contains(' ')
                || v.request.path.contains("..")
                || v.request.path.contains("//")
                || !v.request.path.is_ascii()
                || v.request.path.contains("/./")
        })
        .count();
    assert!(
        discriminating >= 8,
        "corpus lost its discriminating paths ({discriminating}); a canonical-URI \
         regression would go unnoticed again"
    );
}

/// Keeps `CanonicalPathEncoding` honest about which profile each service gets.
#[test]
fn s3_and_non_s3_select_different_canonical_path_encodings() {
    let s3 = SigningScope {
        region: "us-east-1".into(),
        service: "s3".into(),
    };
    let other = SigningScope {
        region: "us-east-1".into(),
        service: "service".into(),
    };
    assert_eq!(s3.canonical_path_encoding(), CanonicalPathEncoding::Single);
    assert_eq!(
        other.canonical_path_encoding(),
        CanonicalPathEncoding::Double
    );
}
