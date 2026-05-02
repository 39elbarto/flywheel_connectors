//! `fwc bootstrap migrate-owner-key` ceremony implementation.
//!
//! The command builds the V3 Ed25519 to V4 ML-DSA-65 bridge attestation and
//! emits a JSON evidence bundle. Secret key material is accepted only from
//! process-local inputs and is never serialized into the evidence bundle.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, ValueEnum};
use fcp_bootstrap::GenesisState;
use fcp_crypto::{
    Ed25519SigningKey, KeyId, ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SEED_SIZE,
    ML_DSA_65_SIGNATURE_SIZE, MlDsa65SigningKey, OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA,
    OWNER_KEY_MIGRATION_DOMAIN, OwnerKeyMigrationAttestation, OwnerKeyMigrationTranscript,
    canonicalize::to_deterministic_cbor,
};
use serde::{Deserialize, Serialize};

const EVIDENCE_SCHEMA: &str = "fcp.owner-key-migration.evidence.v1";
const V4_OWNER_KEY_SCHEMA: &str = "fcp.owner-key.v4.ml-dsa-65.preview.v1";
const CANCELLATION_SCHEMA: &str = "fcp.owner-key-migration.cancellation.v1";
const ROLLBACK_SCHEMA: &str = "fcp.owner-key-migration.rollback.v1";
const CEREMONY_OBJECT_DOMAIN: &[u8] = b"FCP-OWNER-KEY-MIGRATION-CEREMONY-OBJECT-V1";
const V3_SEED_ENV: &str = "FWC_OWNER_V3_ED25519_SEED_HEX";
const V4_SEED_ENV: &str = "FWC_OWNER_V4_ML_DSA_65_SEED_HEX";
const GENESIS_PATH_ENV: &str = "FWC_OWNER_GENESIS_CBOR";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OwnerKeyVersion {
    V3,
    V4,
}

impl OwnerKeyVersion {
    const fn as_str(self) -> &'static str {
        match self {
            Self::V3 => "v3",
            Self::V4 => "v4",
        }
    }
}

#[derive(Args, Debug, Serialize)]
pub struct MigrateOwnerKeyArgs {
    /// Source owner-key generation.
    #[arg(long, value_enum)]
    pub from: OwnerKeyVersion,

    /// Target owner-key generation.
    #[arg(long, value_enum)]
    pub to: OwnerKeyVersion,

    /// Build and verify the ceremony without publishing or requiring durable V3/V4 secret imports.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Write the machine-checkable evidence bundle to this JSON path.
    #[arg(long, value_name = "PATH")]
    pub evidence_bundle: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct MigrateOwnerKeyOutput {
    pub status: String,
    pub command: String,
    pub dry_run: bool,
    pub from: String,
    pub to: String,
    pub evidence_bundle_path: Option<String>,
    pub evidence_bundle_digest: String,
    pub evidence_bundle: OwnerKeyMigrationEvidenceBundle,
    pub next_actions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OwnerKeyMigrationEvidenceBundle {
    pub schema: String,
    pub command: String,
    pub generated_at: DateTime<Utc>,
    pub dry_run: bool,
    pub from: String,
    pub to: String,
    pub migration_epoch: u64,
    pub v3_inventory: V3OwnerInventoryEvidence,
    pub v4_key: V4OwnerKeyEvidence,
    pub migration_attestation: MigrationAttestationEvidence,
    pub cancellation_object: SignedCeremonyObjectEvidence,
    pub rollback_object: SignedCeremonyObjectEvidence,
    pub checks: Vec<CeremonyCheckEvidence>,
    pub secrets_policy: SecretsPolicyEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct V3OwnerInventoryEvidence {
    pub algorithm: String,
    pub source: String,
    pub signing_source: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub genesis: Option<GenesisInventoryEvidence>,
    pub prior_v3_attestation_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GenesisInventoryEvidence {
    pub path: String,
    pub fingerprint: String,
    pub schema_version: u32,
    pub zone_count: usize,
    pub cbor_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct V4OwnerKeyEvidence {
    pub algorithm: String,
    pub source: String,
    pub key_id: String,
    pub public_key_len: usize,
    pub signature_len: usize,
    pub public_key_hash: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct MigrationAttestationEvidence {
    pub schema: String,
    pub domain: String,
    pub prior_v3_kid: String,
    pub new_v4_kid: String,
    pub prior_v3_attestation_hash: String,
    pub new_v4_attestation_hash: String,
    pub migration_epoch: u64,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub transcript_signing_bytes_hash: String,
    pub attestation_cbor_hash: String,
    pub signed_with_v3_ed25519_hex: String,
    pub signed_with_v4_ml_dsa_65_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignedCeremonyObjectEvidence {
    pub schema: String,
    pub object_hash: String,
    pub signing_bytes_hash: String,
    pub signed_with_v3_ed25519_hex: String,
    pub signed_with_v4_ml_dsa_65_hex: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct CeremonyCheckEvidence {
    pub id: String,
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecretsPolicyEvidence {
    pub v3_secret_source: String,
    pub v4_secret_source: String,
    pub secret_material_written_to_disk: bool,
    pub serialized_secret_fields: Vec<String>,
}

struct V3OwnerState {
    signing_key: Ed25519SigningKey,
    inventory: V3OwnerInventoryEvidence,
}

struct V4OwnerState {
    signing_key: MlDsa65SigningKey,
    evidence: V4OwnerKeyEvidence,
}

#[derive(Clone, Debug)]
struct RuntimeInputs {
    now: DateTime<Utc>,
    v3_seed: Option<[u8; 32]>,
    v4_seed: Option<[u8; ML_DSA_65_SEED_SIZE]>,
    genesis_path: Option<PathBuf>,
    allow_ephemeral_dry_run_v3: bool,
    deterministic_signatures: bool,
}

impl RuntimeInputs {
    fn from_process(dry_run: bool) -> Result<Self> {
        Ok(Self {
            now: Utc::now(),
            v3_seed: read_optional_seed_32(V3_SEED_ENV)?,
            v4_seed: read_optional_seed_32(V4_SEED_ENV)?,
            genesis_path: env::var_os(GENESIS_PATH_ENV).map(PathBuf::from),
            allow_ephemeral_dry_run_v3: dry_run,
            deterministic_signatures: false,
        })
    }
}

pub fn run(args: &MigrateOwnerKeyArgs) -> Result<MigrateOwnerKeyOutput> {
    let inputs = RuntimeInputs::from_process(args.dry_run)?;
    run_with_inputs(args, &inputs)
}

fn run_with_inputs(
    args: &MigrateOwnerKeyArgs,
    inputs: &RuntimeInputs,
) -> Result<MigrateOwnerKeyOutput> {
    validate_version_path(args)?;

    let v3 = load_v3_owner_state(args.dry_run, inputs)?;
    let v4 = load_v4_owner_state(inputs)?;
    let migration_epoch = timestamp_epoch(inputs.now)?;
    let not_before_unix = migration_epoch;
    let not_after_unix = timestamp_epoch(inputs.now + Duration::days(7))?;

    let new_v4_attestation_hash = v4_owner_attestation_hash(&v4.evidence)?;
    let prior_v3_attestation_hash = hex_hash_to_array(&v3.inventory.prior_v3_attestation_hash)?;
    let transcript = OwnerKeyMigrationTranscript::new(
        v3.signing_key.key_id(),
        v4.signing_key.verifying_key().key_id(),
        prior_v3_attestation_hash,
        new_v4_attestation_hash,
        migration_epoch,
        not_before_unix,
        not_after_unix,
    );
    let transcript_bytes = transcript.signing_bytes();
    let signed_with_v3 = v3.signing_key.sign(&transcript_bytes);
    let signed_with_v4 = sign_ml_dsa(&v4.signing_key, &transcript_bytes, inputs)?;
    let attestation = OwnerKeyMigrationAttestation::new(
        transcript.clone(),
        signed_with_v3,
        signed_with_v4.clone(),
    );

    v3.signing_key
        .verifying_key()
        .verify(&transcript_bytes, &signed_with_v3)
        .context("failed to verify V3 Ed25519 migration attestation signature")?;
    v4.signing_key
        .verifying_key()
        .verify(&transcript_bytes, b"", &signed_with_v4)
        .context("failed to verify V4 ML-DSA-65 migration attestation signature")?;

    let attestation_evidence =
        build_attestation_evidence(&attestation, &transcript_bytes, &v3.inventory, &v4.evidence)?;
    let cancellation_object = sign_cancellation_object(
        migration_epoch,
        &attestation_evidence.attestation_cbor_hash,
        &v3.signing_key,
        &v4.signing_key,
        inputs,
    )?;
    let rollback_object = sign_rollback_object(
        migration_epoch,
        &attestation_evidence.attestation_cbor_hash,
        &v3.signing_key,
        &v4.signing_key,
        inputs,
    )?;

    let mut bundle = OwnerKeyMigrationEvidenceBundle {
        schema: EVIDENCE_SCHEMA.to_owned(),
        command: "fwc bootstrap migrate-owner-key".to_owned(),
        generated_at: inputs.now,
        dry_run: args.dry_run,
        from: args.from.as_str().to_owned(),
        to: args.to.as_str().to_owned(),
        migration_epoch,
        v3_inventory: v3.inventory,
        v4_key: v4.evidence,
        migration_attestation: attestation_evidence,
        cancellation_object,
        rollback_object,
        checks: Vec::new(),
        secrets_policy: SecretsPolicyEvidence {
            v3_secret_source: v3_secret_source(inputs, args.dry_run),
            v4_secret_source: v4_secret_source(inputs),
            secret_material_written_to_disk: false,
            serialized_secret_fields: Vec::new(),
        },
    };
    bundle.checks = ceremony_checks(&bundle);

    let bundle_bytes = serde_json::to_vec_pretty(&bundle)?;
    let bundle_digest = digest_hex(&bundle_bytes);
    if let Some(path) = &args.evidence_bundle {
        write_evidence_bundle(path, &bundle_bytes)?;
    }

    Ok(MigrateOwnerKeyOutput {
        status: if args.dry_run {
            "dry-run-complete".to_owned()
        } else {
            "migration-attestation-built".to_owned()
        },
        command: "fwc bootstrap migrate-owner-key".to_owned(),
        dry_run: args.dry_run,
        from: args.from.as_str().to_owned(),
        to: args.to.as_str().to_owned(),
        evidence_bundle_path: args
            .evidence_bundle
            .as_ref()
            .map(|path| path.display().to_string()),
        evidence_bundle_digest: bundle_digest,
        evidence_bundle: bundle,
        next_actions: next_actions(args.dry_run),
    })
}

fn validate_version_path(args: &MigrateOwnerKeyArgs) -> Result<()> {
    if args.from != OwnerKeyVersion::V3 || args.to != OwnerKeyVersion::V4 {
        bail!(
            "only the v3 -> v4 owner-key migration path is supported by this ceremony; got {} -> {}",
            args.from.as_str(),
            args.to.as_str()
        );
    }
    Ok(())
}

fn load_v3_owner_state(dry_run: bool, inputs: &RuntimeInputs) -> Result<V3OwnerState> {
    let genesis = load_genesis_inventory(inputs)?;
    let (signing_key, signing_source) = match inputs.v3_seed {
        Some(seed) => (
            Ed25519SigningKey::from_bytes(&seed).context("invalid imported V3 Ed25519 seed")?,
            format!("env:{V3_SEED_ENV}"),
        ),
        None if genesis.is_none() && dry_run && inputs.allow_ephemeral_dry_run_v3 => (
            Ed25519SigningKey::generate(),
            "ephemeral-dry-run-generated".to_owned(),
        ),
        None if genesis.is_some() => bail!(
            "found V3 genesis state but cannot cross-sign without {V3_SEED_ENV}; refusing to fabricate an owner signature"
        ),
        None => bail!(
            "missing V3 owner seed; set {V3_SEED_ENV} to a 32-byte hex Ed25519 seed, or rerun with --dry-run for an ephemeral preview"
        ),
    };

    if let Some(genesis_evidence) = &genesis {
        let signing_public = signing_key.verifying_key().to_bytes();
        if genesis_evidence.owner_public_key != signing_public {
            bail!(
                "imported {V3_SEED_ENV} does not match inventoried genesis owner public key at {}",
                genesis_evidence.evidence.path
            );
        }
    }

    let owner_public = signing_key.verifying_key().to_bytes();
    let prior_hash = genesis
        .as_ref()
        .map(|evidence| evidence.evidence.cbor_hash.clone())
        .unwrap_or_else(|| synthetic_v3_attestation_hash(&owner_public, &signing_source));
    Ok(V3OwnerState {
        inventory: V3OwnerInventoryEvidence {
            algorithm: "ed25519".to_owned(),
            source: genesis
                .as_ref()
                .map(|evidence| evidence.evidence.path.clone())
                .unwrap_or_else(|| signing_source.clone()),
            signing_source,
            key_id: signing_key.key_id().to_hex(),
            public_key_hex: hex::encode(owner_public),
            genesis: genesis.map(|evidence| evidence.evidence),
            prior_v3_attestation_hash: prior_hash,
        },
        signing_key,
    })
}

fn load_v4_owner_state(inputs: &RuntimeInputs) -> Result<V4OwnerState> {
    let (signing_key, source) = match inputs.v4_seed {
        Some(seed) => (
            MlDsa65SigningKey::from_seed(&seed).context("invalid imported V4 ML-DSA-65 seed")?,
            format!("env:{V4_SEED_ENV}"),
        ),
        None => (
            MlDsa65SigningKey::generate().context("failed to generate V4 ML-DSA-65 key")?,
            "generated-in-memory".to_owned(),
        ),
    };
    let verifying_key = signing_key.verifying_key();
    Ok(V4OwnerState {
        evidence: V4OwnerKeyEvidence {
            algorithm: "ml-dsa-65".to_owned(),
            source,
            key_id: verifying_key.key_id().to_hex(),
            public_key_len: verifying_key.as_bytes().len(),
            signature_len: ML_DSA_65_SIGNATURE_SIZE,
            public_key_hash: digest_hex(verifying_key.as_bytes()),
            public_key_hex: hex::encode(verifying_key.as_bytes()),
        },
        signing_key,
    })
}

#[derive(Clone, Debug)]
struct LoadedGenesisInventory {
    owner_public_key: [u8; 32],
    evidence: GenesisInventoryEvidence,
}

fn load_genesis_inventory(inputs: &RuntimeInputs) -> Result<Option<LoadedGenesisInventory>> {
    for path in genesis_candidate_paths(inputs) {
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read V3 genesis state {}", path.display()))?;
        let genesis = GenesisState::from_cbor(&bytes)
            .with_context(|| format!("failed to decode V3 genesis CBOR {}", path.display()))?;
        genesis
            .validate()
            .with_context(|| format!("invalid V3 genesis state {}", path.display()))?;
        return Ok(Some(LoadedGenesisInventory {
            owner_public_key: genesis.owner_public_key,
            evidence: GenesisInventoryEvidence {
                path: path.display().to_string(),
                fingerprint: genesis.fingerprint(),
                schema_version: genesis.schema_version,
                zone_count: genesis.initial_zones.len(),
                cbor_hash: digest_hex(&bytes),
            },
        }));
    }
    Ok(None)
}

fn genesis_candidate_paths(inputs: &RuntimeInputs) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = &inputs.genesis_path {
        candidates.push(path.clone());
    }
    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join(".fcp").join("genesis.cbor"));
        candidates.push(cwd.join(".fcp").join("bootstrap").join("genesis.cbor"));
    }
    if let Some(home) = env::var_os("HOME") {
        let fcp_home = PathBuf::from(home).join(".fcp");
        candidates.push(fcp_home.join("genesis.cbor"));
        candidates.push(fcp_home.join("bootstrap").join("genesis.cbor"));
    }
    candidates
}

fn v4_owner_attestation_hash(evidence: &V4OwnerKeyEvidence) -> Result<[u8; 32]> {
    let unsigned = serde_json::json!({
        "schema": V4_OWNER_KEY_SCHEMA,
        "algorithm": evidence.algorithm,
        "key_id": evidence.key_id,
        "public_key_hash": evidence.public_key_hash,
        "public_key_len": evidence.public_key_len,
    });
    let cbor = to_deterministic_cbor(&unsigned)?;
    Ok(*blake3::hash(&cbor).as_bytes())
}

fn build_attestation_evidence(
    attestation: &OwnerKeyMigrationAttestation,
    transcript_bytes: &[u8],
    v3_inventory: &V3OwnerInventoryEvidence,
    v4_key: &V4OwnerKeyEvidence,
) -> Result<MigrationAttestationEvidence> {
    let attestation_cbor = to_deterministic_cbor(attestation)?;
    Ok(MigrationAttestationEvidence {
        schema: OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA.to_owned(),
        domain: String::from_utf8_lossy(OWNER_KEY_MIGRATION_DOMAIN).to_string(),
        prior_v3_kid: v3_inventory.key_id.clone(),
        new_v4_kid: v4_key.key_id.clone(),
        prior_v3_attestation_hash: v3_inventory.prior_v3_attestation_hash.clone(),
        new_v4_attestation_hash: digest_hex_array(&attestation.transcript.new_v4_attestation_hash),
        migration_epoch: attestation.transcript.migration_epoch,
        not_before_unix: attestation.transcript.not_before_unix,
        not_after_unix: attestation.transcript.not_after_unix,
        transcript_signing_bytes_hash: digest_hex(transcript_bytes),
        attestation_cbor_hash: digest_hex(&attestation_cbor),
        signed_with_v3_ed25519_hex: hex::encode(attestation.signed_with_v3.to_bytes()),
        signed_with_v4_ml_dsa_65_hex: hex::encode(attestation.signed_with_v4.as_bytes()),
    })
}

fn sign_cancellation_object(
    migration_epoch: u64,
    attestation_hash: &str,
    v3: &Ed25519SigningKey,
    v4: &MlDsa65SigningKey,
    inputs: &RuntimeInputs,
) -> Result<SignedCeremonyObjectEvidence> {
    let payload = serde_json::json!({
        "schema": CANCELLATION_SCHEMA,
        "cancels_migration_epoch": migration_epoch,
        "cancellation_epoch": migration_epoch.saturating_add(1),
        "attestation_hash": attestation_hash,
        "effect": "revokes-unpublished-v4-attestation",
        "requires": ["v3-owner-signature", "v4-owner-signature"],
    });
    sign_ceremony_object(CANCELLATION_SCHEMA, payload, v3, v4, inputs)
}

fn sign_rollback_object(
    migration_epoch: u64,
    attestation_hash: &str,
    v3: &Ed25519SigningKey,
    v4: &MlDsa65SigningKey,
    inputs: &RuntimeInputs,
) -> Result<SignedCeremonyObjectEvidence> {
    let payload = serde_json::json!({
        "schema": ROLLBACK_SCHEMA,
        "rolls_back_migration_epoch": migration_epoch,
        "rollback_epoch": migration_epoch.saturating_add(2),
        "attestation_hash": attestation_hash,
        "restores_owner_generation": "v3",
        "revokes_owner_generation": "v4",
        "requires": ["v3-owner-signature", "v4-owner-signature", "majority-receipt-before-publish"],
    });
    sign_ceremony_object(ROLLBACK_SCHEMA, payload, v3, v4, inputs)
}

fn sign_ceremony_object(
    schema: &str,
    payload: serde_json::Value,
    v3: &Ed25519SigningKey,
    v4: &MlDsa65SigningKey,
    inputs: &RuntimeInputs,
) -> Result<SignedCeremonyObjectEvidence> {
    let cbor = to_deterministic_cbor(&payload)?;
    let signing_bytes = ceremony_object_signing_bytes(schema, &cbor);
    let v3_signature = v3.sign(&signing_bytes);
    let v4_signature = sign_ml_dsa(v4, &signing_bytes, inputs)?;
    v3.verifying_key()
        .verify(&signing_bytes, &v3_signature)
        .context("failed to verify signed ceremony object with V3 key")?;
    v4.verifying_key()
        .verify(&signing_bytes, b"", &v4_signature)
        .context("failed to verify signed ceremony object with V4 key")?;
    Ok(SignedCeremonyObjectEvidence {
        schema: schema.to_owned(),
        object_hash: digest_hex(&cbor),
        signing_bytes_hash: digest_hex(&signing_bytes),
        signed_with_v3_ed25519_hex: hex::encode(v3_signature.to_bytes()),
        signed_with_v4_ml_dsa_65_hex: hex::encode(v4_signature.as_bytes()),
        payload,
    })
}

fn ceremony_object_signing_bytes(schema: &str, cbor: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(CEREMONY_OBJECT_DOMAIN.len() + schema.len() + cbor.len() + 4);
    bytes.extend_from_slice(CEREMONY_OBJECT_DOMAIN);
    append_len_prefixed(&mut bytes, schema.as_bytes());
    append_len_prefixed(&mut bytes, cbor);
    bytes
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("ceremony object components fit u32");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
}

fn sign_ml_dsa(
    key: &MlDsa65SigningKey,
    message: &[u8],
    inputs: &RuntimeInputs,
) -> Result<fcp_crypto::MlDsa65SignatureBytes> {
    if inputs.deterministic_signatures {
        key.sign_deterministic(message, b"")
    } else {
        key.sign(message, b"")
    }
    .context("ML-DSA-65 signing failed")
}

fn ceremony_checks(bundle: &OwnerKeyMigrationEvidenceBundle) -> Vec<CeremonyCheckEvidence> {
    vec![
        check("v3-owner-inventoried", true, &bundle.v3_inventory.source),
        check(
            "v4-ml-dsa-65-key-available",
            bundle.v4_key.public_key_len == ML_DSA_65_PUBLIC_KEY_SIZE
                && bundle.v4_key.signature_len == ML_DSA_65_SIGNATURE_SIZE,
            "V4 public-key and signature sizes match FIPS 204 ML-DSA-65",
        ),
        check(
            "migration-attestation-cross-signed",
            !bundle
                .migration_attestation
                .signed_with_v3_ed25519_hex
                .is_empty()
                && !bundle
                    .migration_attestation
                    .signed_with_v4_ml_dsa_65_hex
                    .is_empty(),
            "migration transcript has V3 Ed25519 and V4 ML-DSA-65 signatures",
        ),
        check(
            "cancellation-object-cross-signed",
            !bundle
                .cancellation_object
                .signed_with_v3_ed25519_hex
                .is_empty()
                && !bundle
                    .cancellation_object
                    .signed_with_v4_ml_dsa_65_hex
                    .is_empty(),
            "cancellation object can revoke an unpublished migration",
        ),
        check(
            "rollback-object-cross-signed",
            !bundle.rollback_object.signed_with_v3_ed25519_hex.is_empty()
                && !bundle
                    .rollback_object
                    .signed_with_v4_ml_dsa_65_hex
                    .is_empty(),
            "rollback object restores the V3 owner generation if V4 publish fails",
        ),
        check(
            "no-secret-material-serialized",
            !bundle.secrets_policy.secret_material_written_to_disk
                && bundle.secrets_policy.serialized_secret_fields.is_empty(),
            "evidence bundle contains only public keys, key identifiers, hashes, and signatures",
        ),
    ]
}

fn check(id: &str, passed: bool, detail: &str) -> CeremonyCheckEvidence {
    CeremonyCheckEvidence {
        id: id.to_owned(),
        status: if passed { "pass" } else { "fail" }.to_owned(),
        detail: detail.to_owned(),
    }
}

fn synthetic_v3_attestation_hash(public_key: &[u8; 32], source: &str) -> String {
    let unsigned = serde_json::json!({
        "schema": "fcp.owner-key.v3.inventory.v1",
        "algorithm": "ed25519",
        "source": source,
        "public_key_hex": hex::encode(public_key),
        "key_id": KeyId::derive_from_public_key(public_key).to_hex(),
    });
    let cbor = to_deterministic_cbor(&unsigned).expect("synthetic V3 inventory is serializable");
    digest_hex(&cbor)
}

fn hex_hash_to_array(hash: &str) -> Result<[u8; 32]> {
    let hex_hash = hash
        .strip_prefix("blake3-256:")
        .ok_or_else(|| anyhow::anyhow!("expected blake3-256 hash prefix"))?;
    let bytes = hex::decode(hex_hash).context("invalid blake3 hash hex")?;
    if bytes.len() != 32 {
        bail!("expected 32-byte blake3 hash, got {} bytes", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn digest_hex(bytes: &[u8]) -> String {
    digest_hex_array(blake3::hash(bytes).as_bytes())
}

fn digest_hex_array(bytes: &[u8; 32]) -> String {
    format!("blake3-256:{}", hex::encode(bytes))
}

fn read_optional_seed_32<const N: usize>(name: &str) -> Result<Option<[u8; N]>> {
    let Some(raw) = env::var_os(name) else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} must be valid UTF-8 hex"))?;
    let bytes = hex::decode(raw.trim()).with_context(|| format!("{name} is not valid hex"))?;
    if bytes.len() != N {
        bail!("{name} must decode to {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

fn timestamp_epoch(value: DateTime<Utc>) -> Result<u64> {
    u64::try_from(value.timestamp()).context("migration timestamps must not predate Unix epoch")
}

fn write_evidence_bundle(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create evidence bundle parent directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(path, bytes)
        .with_context(|| format!("failed to write evidence bundle {}", path.display()))
}

fn v3_secret_source(inputs: &RuntimeInputs, dry_run: bool) -> String {
    if inputs.v3_seed.is_some() {
        format!("env:{V3_SEED_ENV}")
    } else if dry_run {
        "ephemeral-dry-run-generated".to_owned()
    } else {
        "missing".to_owned()
    }
}

fn v4_secret_source(inputs: &RuntimeInputs) -> String {
    if inputs.v4_seed.is_some() {
        format!("env:{V4_SEED_ENV}")
    } else {
        "generated-in-memory".to_owned()
    }
}

fn next_actions(dry_run: bool) -> Vec<String> {
    if dry_run {
        vec![
            format!("Import the real V3 owner seed through {V3_SEED_ENV} before publishing."),
            format!("Import or escrow the real V4 ML-DSA-65 seed through {V4_SEED_ENV} or a hardware-backed provider before publishing."),
            "Review the emitted cancellation and rollback objects before advancing the owner generation.".to_owned(),
        ]
    } else {
        vec![
            "Publish the migration attestation only after the evidence bundle is archived."
                .to_owned(),
            "Retain the cancellation object until V4 owner state has majority acceptance."
                .to_owned(),
            "Retain the rollback object until all V3 acceptance windows have expired.".to_owned(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_large_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .name("bootstrap-migrate-owner-key-test".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn(f)
            .expect("large-stack test thread spawns")
            .join()
            .expect("large-stack test thread completes")
    }

    fn fixed_inputs() -> RuntimeInputs {
        RuntimeInputs {
            now: DateTime::from_timestamp(1_765_000_000, 0).expect("fixed timestamp is valid"),
            v3_seed: Some([0x11; 32]),
            v4_seed: Some([0x22; ML_DSA_65_SEED_SIZE]),
            genesis_path: None,
            allow_ephemeral_dry_run_v3: true,
            deterministic_signatures: true,
        }
    }

    fn fixed_args(path: Option<PathBuf>) -> MigrateOwnerKeyArgs {
        MigrateOwnerKeyArgs {
            from: OwnerKeyVersion::V3,
            to: OwnerKeyVersion::V4,
            dry_run: true,
            evidence_bundle: path,
        }
    }

    #[test]
    fn bootstrap_migrate_owner_key_builds_cross_signed_bundle() {
        let output =
            with_large_stack(|| run_with_inputs(&fixed_args(None), &fixed_inputs()).unwrap());

        assert_eq!(output.status, "dry-run-complete");
        assert_eq!(output.evidence_bundle.schema, EVIDENCE_SCHEMA);
        assert_eq!(output.evidence_bundle.v3_inventory.algorithm, "ed25519");
        assert_eq!(output.evidence_bundle.v4_key.algorithm, "ml-dsa-65");
        assert_eq!(
            output.evidence_bundle.v4_key.public_key_len,
            ML_DSA_65_PUBLIC_KEY_SIZE
        );
        assert!(
            output
                .evidence_bundle
                .checks
                .iter()
                .all(|check| check.status == "pass")
        );
        assert!(
            output
                .evidence_bundle
                .migration_attestation
                .attestation_cbor_hash
                .starts_with("blake3-256:")
        );
    }

    #[test]
    fn bootstrap_migrate_owner_key_writes_machine_checkable_evidence_bundle() {
        with_large_stack(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("owner-migration.json");
            let output = run_with_inputs(&fixed_args(Some(path.clone())), &fixed_inputs()).unwrap();

            let bytes = fs::read(&path).unwrap();
            assert_eq!(output.evidence_bundle_digest, digest_hex(&bytes));
            let bundle: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(bundle["schema"], EVIDENCE_SCHEMA);
            assert_eq!(bundle["cancellation_object"]["schema"], CANCELLATION_SCHEMA);
            assert_eq!(bundle["rollback_object"]["schema"], ROLLBACK_SCHEMA);
        });
    }

    #[test]
    fn bootstrap_migrate_owner_key_evidence_does_not_serialize_seed_material() {
        let output =
            with_large_stack(|| run_with_inputs(&fixed_args(None), &fixed_inputs()).unwrap());
        let json = serde_json::to_string(&output.evidence_bundle).unwrap();

        assert!(!json.contains(&hex::encode([0x11; 32])));
        assert!(!json.contains(&hex::encode([0x22; ML_DSA_65_SEED_SIZE])));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("secret_key"));
        assert!(
            !output
                .evidence_bundle
                .secrets_policy
                .secret_material_written_to_disk
        );
    }
}
