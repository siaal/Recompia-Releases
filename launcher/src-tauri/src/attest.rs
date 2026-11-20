// SPDX-License-Identifier: GPL-3.0-or-later
//! Build provenance: an update is installed only when its package carries a valid attestation that the release workflow of the
//! release repository built it, from the commit the release's tag names.
//!
//! release.yml's publish job attests every archive (actions/attest-build-provenance): a Sigstore bundle holding a DSSE envelope with
//! an in-toto SLSA provenance statement, signed with a short-lived Fulcio certificate that records which workflow run asked for it,
//! and logged in Rekor, whose signed entry timestamp (SET) says when. GitHub keeps the bundles (`/repos/<repo>/attestations/sha256:<hex>`);
//! where they come from does not matter, because everything is checked here against keys built into the launcher:
//! 1. the Rekor SET, signed by the Rekor key, over the log entry: the signing time is then trusted;
//! 2. the certificate chain: the leaf signed by the Fulcio intermediate, the intermediate by the Fulcio root, both valid then;
//! 3. the leaf's GitHub Actions claims (`Policy`): this repository, this workflow, a GitHub-hosted runner, a ref the release can be
//!    built from, and the tag's commit;
//! 4. the DSSE signature over the statement with the leaf's key, and that the log entry is for this envelope and this certificate;
//! 5. the statement: SLSA provenance v1 for a subject with this name and SHA-256.
//!
//! Not checked: the certificate's embedded SCT (Certificate Transparency) and the Merkle inclusion proof. The SET is Rekor's signed
//! promise of inclusion, which is what `cosign` and `gh attestation verify` accept as well.
//!
//! The keys are those of Sigstore's public-good instance (trusted_root.json from tuf-repo-cdn.sigstore.dev, sha256
//! 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66): the Fulcio CA valid from 2022-04-13 (root and intermediate
//! valid to 2031-10-05) and the Rekor v1 log (rekor.sigstore.dev). release.yml pins actions/attest-build-provenance to a commit, so
//! the bundles keep this form (a Rekor v1 `dsse` entry with a SET); moving that pin means checking that the launcher still verifies.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Header, Reader, SliceReader};
use x509_cert::spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;

/// The Rekor v1 log's public key (SPKI DER, ECDSA P-256).
const REKOR_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";
/// The Fulcio intermediate certificate (CN=sigstore-intermediate), which signs every leaf.
const FULCIO_INTERMEDIATE: &str = "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=";
/// The Fulcio root certificate (CN=sigstore), which signs the intermediate.
const FULCIO_ROOT: &str = "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ";

/// The workflow that builds and attests the release packages.
pub const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
/// Where release.yml may run from besides the tag itself: a manual run publishes stable releases from main, Testing ones from testing.
const RELEASE_BRANCHES: [&str; 2] = ["refs/heads/main", "refs/heads/testing"];
const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const IN_TOTO_PAYLOAD: &str = "application/vnd.in-toto+json";
const IN_TOTO_STATEMENT: &str = "https://in-toto.io/Statement/v1";
const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/v1";
/// Bundles read per package at most, and the size of one (compressed and not): a repository cannot make the launcher read without end.
const MAX_BUNDLES: usize = 10;
const BUNDLE_LIMIT: usize = 4 << 20;
const API_LIMIT: u64 = 4 << 20;

// Fulcio's certificate extensions (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md), DER UTF8String values.
const OID_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
const OID_BUILD_SIGNER_URI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9");
const OID_RUNNER_ENVIRONMENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.11");
const OID_SOURCE_REPOSITORY_URI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.12");
const OID_SOURCE_REPOSITORY_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
const OID_SOURCE_REPOSITORY_REF: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.14");
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Who must have built the package: the leaf certificate's GitHub Actions claims are held to these.
pub struct Policy<'a> {
    /// `owner/name`
    pub repo: &'a str,
    /// the workflow file, e.g. `.github/workflows/release.yml`
    pub workflow: &'a str,
    /// the refs the workflow may have run from
    pub refs: &'a [String],
    /// the commit the release's tag names (40 hex digits)
    pub commit: &'a str,
}

/// The file the statement must name.
pub struct Subject<'a> {
    pub name: &'a str,
    /// lower-case hex
    pub sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    media_type: String,
    verification_material: Material,
    dsse_envelope: Option<Envelope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Material {
    /// bundle v0.3
    certificate: Option<RawBytes>,
    /// bundle v0.1 and v0.2: the leaf first
    x509_certificate_chain: Option<Chain>,
    #[serde(default)]
    tlog_entries: Vec<TlogEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBytes {
    raw_bytes: String,
}

#[derive(Deserialize)]
struct Chain {
    certificates: Vec<RawBytes>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogEntry {
    log_index: String,
    log_id: LogId,
    kind_version: KindVersion,
    integrated_time: String,
    inclusion_promise: Option<Promise>,
    canonicalized_body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

#[derive(Deserialize)]
struct KindVersion {
    kind: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Promise {
    signed_entry_timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    payload: String,
    payload_type: String,
    signatures: Vec<EnvelopeSig>,
}

#[derive(Deserialize)]
struct EnvelopeSig {
    sig: String,
}

/// The `canonicalizedBody` of a Rekor `dsse` 0.0.1 entry: what was logged.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorBody {
    kind: String,
    api_version: String,
    spec: DsseSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseSpec {
    payload_hash: Hash,
    signatures: Vec<LoggedSig>,
}

#[derive(Deserialize)]
struct Hash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
struct LoggedSig {
    signature: String,
    /// the signing certificate, PEM, base64
    verifier: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    predicate_type: String,
    subject: Vec<StatementSubject>,
}

#[derive(Deserialize)]
struct StatementSubject {
    #[serde(default)]
    name: String,
    #[serde(default)]
    digest: HashMap<String, String>,
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| format!("{what} is not base64 ({e})"))
}

fn pinned_cert(b64_der: &str) -> Certificate {
    let der = B64.decode(b64_der).expect("a pinned Sigstore certificate is base64");
    Certificate::from_der(&der).expect("a pinned Sigstore certificate parses")
}

/// The DER bytes of the first element inside the outer SEQUENCE of `der`: a certificate's TBSCertificate exactly as it was signed.
fn signed_part(der: &[u8]) -> Result<&[u8], String> {
    let mut r = SliceReader::new(der).map_err(|e| e.to_string())?;
    Header::decode(&mut r).map_err(|e| format!("certificate: {e}"))?;
    r.tlv_bytes().map_err(|e| format!("certificate: {e}"))
}

/// Checks an ASN.1 ECDSA signature by an EC key (`curve` from its SPKI, `point` the uncompressed point), hashed per `alg`.
fn ecdsa_ok(curve: &ObjectIdentifier, point: &[u8], alg: &ObjectIdentifier, message: &[u8], sig: &[u8]) -> Result<(), String> {
    let scheme: &dyn signature::VerificationAlgorithm = match (curve, alg) {
        (c, a) if *c == OID_P256 && *a == OID_ECDSA_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
        (c, a) if *c == OID_P256 && *a == OID_ECDSA_SHA384 => &signature::ECDSA_P256_SHA384_ASN1,
        (c, a) if *c == OID_P384 && *a == OID_ECDSA_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
        (c, a) if *c == OID_P384 && *a == OID_ECDSA_SHA256 => &signature::ECDSA_P384_SHA256_ASN1,
        _ => return Err(format!("unsupported key or signature algorithm ({curve}, {alg})")),
    };
    UnparsedPublicKey::new(scheme, point).verify(message, sig).map_err(|_| "signature does not verify".to_string())
}

/// (curve, uncompressed point) of an EC public key.
fn ec_key(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<(ObjectIdentifier, Vec<u8>), String> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(format!("not an EC key ({})", spki.algorithm.oid));
    }
    let curve = spki.algorithm.parameters.as_ref().ok_or("EC key without a curve")?.decode_as::<ObjectIdentifier>().map_err(|e| e.to_string())?;
    let point = spki.subject_public_key.as_bytes().ok_or("EC key with unused bits")?;
    Ok((curve, point.to_vec()))
}

/// `child` is signed by `parent`'s key and names `parent` as its issuer.
fn signed_by(child: &Certificate, child_der: &[u8], parent: &Certificate) -> Result<(), String> {
    if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
        return Err("issuer does not match".into());
    }
    let (curve, point) = ec_key(&parent.tbs_certificate.subject_public_key_info)?;
    let sig = child.signature.as_bytes().ok_or("signature with unused bits")?;
    ecdsa_ok(&curve, &point, &child.signature_algorithm.oid, signed_part(child_der)?, sig)
}

/// `cert` was valid at `t` (Unix seconds).
fn valid_at(cert: &Certificate, t: u64) -> bool {
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_unix_duration().as_secs() <= t && t <= v.not_after.to_unix_duration().as_secs()
}

/// A Fulcio extension's UTF8String value; None when the certificate does not have it.
fn claim(cert: &Certificate, oid: ObjectIdentifier) -> Result<Option<String>, String> {
    let Some(ext) = cert.tbs_certificate.extensions.iter().flatten().find(|e| e.extn_id == oid) else { return Ok(None) };
    let s = x509_cert::der::asn1::Utf8StringRef::from_der(ext.extn_value.as_bytes()).map_err(|e| format!("extension {oid}: {e}"))?;
    Ok(Some(s.as_str().to_string()))
}

fn require_claim(cert: &Certificate, oid: ObjectIdentifier, what: &str) -> Result<String, String> {
    claim(cert, oid)?.ok_or_else(|| format!("the certificate has no {what}"))
}

/// The leaf's GitHub Actions claims against `policy`.
fn check_policy(leaf: &Certificate, policy: &Policy) -> Result<(), String> {
    let issuer = require_claim(leaf, OID_ISSUER, "OIDC issuer")?;
    if issuer != GITHUB_ACTIONS_ISSUER {
        return Err(format!("signed by an identity from {issuer}, not GitHub Actions"));
    }
    let repo_uri = format!("https://github.com/{}", policy.repo);
    let source = require_claim(leaf, OID_SOURCE_REPOSITORY_URI, "source repository")?;
    if !source.eq_ignore_ascii_case(&repo_uri) {
        return Err(format!("built from {source}, not {repo_uri}"));
    }
    let git_ref = require_claim(leaf, OID_SOURCE_REPOSITORY_REF, "source ref")?;
    if !policy.refs.contains(&git_ref) {
        return Err(format!("built from {git_ref}, not from the release's tag or a release branch"));
    }
    let want_signer = format!("{repo_uri}/{}@{git_ref}", policy.workflow);
    let signer = require_claim(leaf, OID_BUILD_SIGNER_URI, "build signer")?;
    if !signer.eq_ignore_ascii_case(&want_signer) {
        return Err(format!("built by {signer}, not {want_signer}"));
    }
    let commit = require_claim(leaf, OID_SOURCE_REPOSITORY_DIGEST, "source commit")?;
    if !commit.eq_ignore_ascii_case(policy.commit) {
        return Err(format!("built from commit {commit}, but the release's tag is commit {}", policy.commit));
    }
    let runner = require_claim(leaf, OID_RUNNER_ENVIRONMENT, "runner environment")?;
    if runner != "github-hosted" {
        return Err(format!("built on a {runner} runner, not a GitHub-hosted one"));
    }
    Ok(())
}

/// DSSE's pre-authentication encoding: what the envelope's signature is over.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    m.extend_from_slice(payload);
    m
}

/// The DER inside a PEM certificate.
fn pem_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("-----")).collect();
    b64(&body, "the logged certificate")
}

/// Rekor's SET over `entry`, with the pinned Rekor key: Ok(the time the entry was logged, Unix seconds).
fn check_set(entry: &TlogEntry) -> Result<u64, String> {
    let key_der = B64.decode(REKOR_KEY).expect("the pinned Rekor key is base64");
    let key = SubjectPublicKeyInfoRef::from_der(&key_der).expect("the pinned Rekor key parses");
    let log_id = Sha256::digest(&key_der);
    if b64(&entry.log_id.key_id, "the log id")? != log_id.as_slice() {
        return Err("logged in a transparency log the launcher does not know".into());
    }
    let promise = entry.inclusion_promise.as_ref().ok_or("the log entry has no signed entry timestamp")?;
    let integrated: u64 = entry.integrated_time.parse().map_err(|_| "the log entry's time is not a number")?;
    let index: u64 = entry.log_index.parse().map_err(|_| "the log entry's index is not a number")?;
    // Rekor signs the canonical JSON (keys sorted, no spaces) of the entry's body, time, log id (hex) and index
    let hex: String = log_id.iter().map(|b| format!("{b:02x}")).collect();
    let signed = format!(
        r#"{{"body":{},"integratedTime":{integrated},"logID":"{hex}","logIndex":{index}}}"#,
        serde_json::to_string(&entry.canonicalized_body).map_err(|e| e.to_string())?
    );
    let curve = key.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok()).expect("the pinned Rekor key has a curve");
    let point = key.subject_public_key.as_bytes().expect("the pinned Rekor key is a whole point");
    ecdsa_ok(&curve, point, &OID_ECDSA_SHA256, signed.as_bytes(), &b64(&promise.signed_entry_timestamp, "the signed entry timestamp")?)
        .map_err(|_| "the transparency log's signed entry timestamp does not verify".to_string())?;
    Ok(integrated)
}

/// The log entry records this envelope's payload and signature, made with this certificate.
fn check_logged(entry: &TlogEntry, payload: &[u8], sig: &[u8], leaf_der: &[u8]) -> Result<(), String> {
    let body: RekorBody = serde_json::from_slice(&b64(&entry.canonicalized_body, "the log entry")?).map_err(|e| format!("the log entry: {e}"))?;
    if body.kind != "dsse" || body.api_version != "0.0.1" {
        return Err(format!("the log entry is a {} {} entry, not dsse 0.0.1", body.kind, body.api_version));
    }
    let want: String = Sha256::digest(payload).iter().map(|b| format!("{b:02x}")).collect();
    if body.spec.payload_hash.algorithm != "sha256" || !body.spec.payload_hash.value.eq_ignore_ascii_case(&want) {
        return Err("the log entry is for another statement".into());
    }
    let [logged] = body.spec.signatures.as_slice() else { return Err("the log entry does not hold exactly one signature".into()) };
    if b64(&logged.signature, "the logged signature")? != sig {
        return Err("the log entry holds another signature".into());
    }
    let pem = String::from_utf8(b64(&logged.verifier, "the logged certificate")?).map_err(|_| "the logged certificate is not PEM")?;
    if pem_der(&pem)? != leaf_der {
        return Err("the log entry was signed with another certificate".into());
    }
    Ok(())
}

/// Verifies one Sigstore bundle (JSON) for `subject` against `policy`, as the header describes. Err: why it is not accepted.
pub fn verify_bundle(json: &[u8], subject: &Subject, policy: &Policy) -> Result<(), String> {
    assert!(subject.sha256.len() == 64 && subject.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "subject digest is lower-case hex");
    assert!(policy.commit.len() == 40, "policy commit is a full SHA-1");
    let bundle: Bundle = serde_json::from_slice(json).map_err(|e| format!("not a Sigstore bundle ({e})"))?;
    if !bundle.media_type.starts_with("application/vnd.dev.sigstore.bundle") {
        return Err(format!("not a Sigstore bundle ({})", bundle.media_type));
    }
    let m = &bundle.verification_material;
    let leaf_b64 = match (&m.certificate, &m.x509_certificate_chain) {
        (Some(c), _) => &c.raw_bytes,
        (None, Some(chain)) => &chain.certificates.first().ok_or("the bundle's certificate chain is empty")?.raw_bytes,
        (None, None) => return Err("the bundle has no signing certificate".into()),
    };
    let leaf_der = b64(leaf_b64, "the signing certificate")?;
    let leaf = Certificate::from_der(&leaf_der).map_err(|e| format!("the signing certificate: {e}"))?;

    // 1. the time of signing, from the transparency log
    let entry = m
        .tlog_entries
        .iter()
        .find(|e| e.kind_version.kind == "dsse" && e.kind_version.version == "0.0.1")
        .ok_or("the bundle has no transparency log entry the launcher can check")?;
    let signed_at = check_set(entry)?;

    // 2. the certificate chain, valid at that time
    let (intermediate, root) = (pinned_cert(FULCIO_INTERMEDIATE), pinned_cert(FULCIO_ROOT));
    signed_by(&intermediate, &B64.decode(FULCIO_INTERMEDIATE).expect("pinned"), &root).map_err(|e| format!("the pinned Fulcio chain: {e}"))?;
    signed_by(&leaf, &leaf_der, &intermediate).map_err(|e| format!("the signing certificate is not from Sigstore's Fulcio: {e}"))?;
    if !valid_at(&leaf, signed_at) || !valid_at(&intermediate, signed_at) {
        return Err("the signing certificate was not valid when the attestation was logged".into());
    }
    let eku = leaf.tbs_certificate.extensions.iter().flatten().find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE).ok_or("the signing certificate has no extended key usage")?;
    let eku = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku.extn_value.as_bytes()).map_err(|e| format!("extended key usage: {e}"))?;
    if !eku.0.contains(&OID_CODE_SIGNING) {
        return Err("the signing certificate is not for code signing".into());
    }

    // 3. who built it
    check_policy(&leaf, policy)?;

    // 4. the envelope's signature, and that the log entry is this envelope's
    let env = bundle.dsse_envelope.as_ref().ok_or("the bundle holds no DSSE envelope")?;
    if env.payload_type != IN_TOTO_PAYLOAD {
        return Err(format!("the envelope holds {}, not an in-toto statement", env.payload_type));
    }
    let [sig] = env.signatures.as_slice() else { return Err("the envelope does not hold exactly one signature".into()) };
    let (payload, sig) = (b64(&env.payload, "the statement")?, b64(&sig.sig, "the envelope signature")?);
    let (curve, point) = ec_key(&leaf.tbs_certificate.subject_public_key_info)?;
    let hash = if curve == OID_P384 { OID_ECDSA_SHA384 } else { OID_ECDSA_SHA256 };
    ecdsa_ok(&curve, &point, &hash, &pae(&env.payload_type, &payload), &sig).map_err(|e| format!("the envelope: {e}"))?;
    check_logged(entry, &payload, &sig, &leaf_der)?;

    // 5. what it says
    let st: Statement = serde_json::from_slice(&payload).map_err(|e| format!("the statement: {e}"))?;
    if st.kind != IN_TOTO_STATEMENT || st.predicate_type != SLSA_PROVENANCE {
        return Err(format!("the statement is a {} {}, not SLSA provenance v1", st.kind, st.predicate_type));
    }
    let named = st.subject.iter().any(|s| s.name == subject.name && s.digest.get("sha256").is_some_and(|d| d.eq_ignore_ascii_case(subject.sha256)));
    if !named {
        return Err(format!("the attestation is not for {} with this checksum", subject.name));
    }
    Ok(())
}

/// One entry of GitHub's attestations list: the bundle inline, or where to fetch it (snappy-compressed).
#[derive(Deserialize)]
struct Listed {
    bundle: Option<serde_json::Value>,
    bundle_url: Option<String>,
}

#[derive(Deserialize)]
struct Listing {
    attestations: Vec<Listed>,
}

#[derive(Deserialize)]
struct GitRef {
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

/// The commit `tag` names in `repo` (an annotated tag is followed to its commit).
fn tag_commit(agent: &ureq::Agent, repo: &str, tag: &str) -> Result<String, String> {
    let read = |url: &str| -> Result<GitObject, String> {
        let body = crate::releases::get(agent, url, API_LIMIT).map_err(|e| format!("could not read the release's tag: {e}"))?;
        serde_json::from_slice::<GitRef>(&body).map(|r| r.object).map_err(|e| format!("could not read the release's tag: {e}"))
    };
    let mut obj = read(&format!("https://api.github.com/repos/{repo}/git/ref/tags/{tag}"))?;
    if obj.kind == "tag" {
        eprintln!("attest.tag_commit.annotated tag={tag}");
        obj = read(&format!("https://api.github.com/repos/{repo}/git/tags/{}", obj.sha))?;
    }
    if obj.kind != "commit" || obj.sha.len() != 40 || !obj.sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("attest.tag_commit.not_commit tag={tag} kind={}", obj.kind);
        return Err(format!("the release's tag does not name a commit ({})", obj.kind));
    }
    Ok(obj.sha.to_ascii_lowercase())
}

/// A bundle's JSON: inline in the list, else fetched from its address and decompressed (snappy, as GitHub stores it).
fn bundle_json(agent: &ureq::Agent, a: &Listed) -> Result<Vec<u8>, String> {
    if let Some(b) = &a.bundle {
        return serde_json::to_vec(b).map_err(|e| e.to_string());
    }
    let url = a.bundle_url.as_deref().filter(|u| u.starts_with("https://")).ok_or("the attestation has no bundle")?;
    let packed = crate::releases::get(agent, url, BUNDLE_LIMIT as u64).map_err(|e| format!("could not download the attestation: {e}"))?;
    let len = snap::raw::decompress_len(&packed).map_err(|e| format!("the attestation is not snappy data: {e}"))?;
    if len > BUNDLE_LIMIT {
        return Err("the attestation is too large".into());
    }
    snap::raw::Decoder::new().decompress_vec(&packed).map_err(|e| format!("the attestation is not snappy data: {e}"))
}

/// Verifies that `repo`'s release workflow built `asset` (SHA-256 `sha256`, lower-case hex) for the release `tag`, from the commit
/// the tag names. Err: why not, for the player.
pub fn verify_release(agent: &ureq::Agent, repo: &str, tag: &str, asset: &str, sha256: &str) -> Result<(), String> {
    verify_built(agent, repo, RELEASE_WORKFLOW, &RELEASE_BRANCHES, tag, asset, sha256)
}

/// `verify_release` for any workflow and branches (the network test checks another project's release with it).
fn verify_built(agent: &ureq::Agent, repo: &str, workflow: &str, branches: &[&str], tag: &str, asset: &str, sha256: &str) -> Result<(), String> {
    if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
        eprintln!("attest.verify_release.bad_tag tag={tag:?}");
        return Err("the release's tag has characters a release tag never has".into());
    }
    let commit = tag_commit(agent, repo, tag)?;
    eprintln!("attest.verify_release.tag tag={tag} commit={commit}");
    let url = format!("https://api.github.com/repos/{repo}/attestations/sha256:{sha256}?predicate_type=https%3A%2F%2Fslsa.dev%2Fprovenance%2Fv1");
    let body = crate::releases::get(agent, &url, API_LIMIT).map_err(|e| {
        eprintln!("attest.verify_release.list_failed asset={asset} error={e}");
        format!("no build attestation could be read for {asset} ({e})")
    })?;
    let listing: Listing = serde_json::from_slice(&body).map_err(|e| format!("GitHub's attestation list could not be read ({e})"))?;
    let mut reasons = Vec::new();
    let refs: Vec<String> = std::iter::once(format!("refs/tags/{tag}")).chain(branches.iter().map(|b| b.to_string())).collect();
    let policy = Policy { repo, workflow, refs: &refs, commit: &commit };
    let subject = Subject { name: asset, sha256 };
    for (i, a) in listing.attestations.iter().take(MAX_BUNDLES).enumerate() {
        match bundle_json(agent, a).and_then(|json| verify_bundle(&json, &subject, &policy)) {
            Ok(()) => {
                eprintln!("attest.verify_release.ok asset={asset} tag={tag} bundle={i}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("attest.verify_release.rejected asset={asset} bundle={i} reason={e}");
                reasons.push(e);
            }
        }
    }
    if reasons.is_empty() {
        eprintln!("attest.verify_release.none asset={asset}");
        return Err(format!("{asset} has no build attestation"));
    }
    Err(reasons.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub CLI's provenance for its v2.105.0 release, exactly as GitHub serves it (snappy): a real bundle of the kind
    /// release.yml makes, signed by Sigstore's public-good Fulcio and logged in Rekor v1.
    const GH_BUNDLE: &[u8] = include_bytes!("../testdata/gh-2.105.0-provenance.json.sn");
    const GH_ASSET: &str = "gh_2.105.0_linux_amd64.tar.gz";
    const GH_SHA256: &str = "79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f";
    const GH_COMMIT: &str = "e1219499a578b69e3437adaa31cd60614e23c802";

    fn gh_json() -> Vec<u8> {
        snap::raw::Decoder::new().decompress_vec(GH_BUNDLE).unwrap()
    }

    fn gh_refs() -> Vec<String> {
        vec!["refs/tags/v2.105.0".into(), "refs/heads/trunk".into()]
    }

    fn gh_check(json: &[u8], subject: &Subject, repo: &str, workflow: &str, refs: &[String], commit: &str) -> Result<(), String> {
        verify_bundle(json, subject, &Policy { repo, workflow, refs, commit })
    }

    fn gh_ok(json: &[u8]) -> Result<(), String> {
        gh_check(json, &Subject { name: GH_ASSET, sha256: GH_SHA256 }, "cli/cli", ".github/workflows/deployment.yml", &gh_refs(), GH_COMMIT)
    }

    /// The bundle with `edit` applied to its JSON.
    fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_slice(&gh_json()).unwrap();
        edit(&mut v);
        serde_json::to_vec(&v).unwrap()
    }

    fn reason(r: Result<(), String>) -> String {
        r.expect_err("the bundle must be refused")
    }

    #[test]
    fn a_real_release_attestation_verifies() {
        assert_eq!(gh_ok(&gh_json()), Ok(()));
    }

    #[test]
    fn the_pinned_keys_are_sigstores() {
        let key = B64.decode(REKOR_KEY).unwrap();
        assert_eq!(B64.encode(Sha256::digest(&key)), "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=", "Rekor's log id is the hash of its key");
        let (i, r) = (pinned_cert(FULCIO_INTERMEDIATE), pinned_cert(FULCIO_ROOT));
        assert_eq!(signed_by(&i, &B64.decode(FULCIO_INTERMEDIATE).unwrap(), &r), Ok(()));
        assert_eq!(signed_by(&r, &B64.decode(FULCIO_ROOT).unwrap(), &r), Ok(()), "the root is self-signed");
    }

    #[test]
    fn another_file_or_checksum_is_refused() {
        let json = gh_json();
        let wrong_sum = "0".repeat(64);
        for (name, sum) in [(GH_ASSET, wrong_sum.as_str()), ("gh_2.105.0_windows_amd64.zip", GH_SHA256)] {
            let r = gh_check(&json, &Subject { name, sha256: sum }, "cli/cli", ".github/workflows/deployment.yml", &gh_refs(), GH_COMMIT);
            assert!(reason(r).contains("not for"));
        }
    }

    #[test]
    fn another_builder_is_refused() {
        let json = gh_json();
        let s = Subject { name: GH_ASSET, sha256: GH_SHA256 };
        let wf = ".github/workflows/deployment.yml";
        assert!(reason(gh_check(&json, &s, "someone/cli", wf, &gh_refs(), GH_COMMIT)).contains("built from https://github.com/cli/cli"));
        assert!(reason(gh_check(&json, &s, "cli/cli", RELEASE_WORKFLOW, &gh_refs(), GH_COMMIT)).contains("built by"));
        assert!(reason(gh_check(&json, &s, "cli/cli", wf, &["refs/tags/v2.105.0".into()], GH_COMMIT)).contains("refs/heads/trunk"));
        assert!(reason(gh_check(&json, &s, "cli/cli", wf, &gh_refs(), &"a".repeat(40))).contains("commit"));
    }

    #[test]
    fn a_changed_statement_is_refused() {
        // the subject list rewritten to name another digest: the envelope signature no longer covers it
        let json = edited(|v| {
            let p = v["dsseEnvelope"]["payload"].as_str().unwrap();
            let mut st: serde_json::Value = serde_json::from_slice(&B64.decode(p).unwrap()).unwrap();
            st["subject"][0]["digest"]["sha256"] = "1".repeat(64).into();
            v["dsseEnvelope"]["payload"] = B64.encode(serde_json::to_vec(&st).unwrap()).into();
        });
        assert!(reason(gh_ok(&json)).contains("the envelope"));
    }

    #[test]
    fn a_changed_log_entry_is_refused() {
        let later = edited(|v| {
            let t: u64 = v["verificationMaterial"]["tlogEntries"][0]["integratedTime"].as_str().unwrap().parse().unwrap();
            v["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (t + 1).to_string().into();
        });
        assert!(reason(gh_ok(&later)).contains("signed entry timestamp"));
        let no_set = edited(|v| {
            v["verificationMaterial"]["tlogEntries"][0].as_object_mut().unwrap().remove("inclusionPromise");
        });
        assert!(reason(gh_ok(&no_set)).contains("no signed entry timestamp"));
        let no_log = edited(|v| v["verificationMaterial"]["tlogEntries"] = serde_json::json!([]));
        assert!(reason(gh_ok(&no_log)).contains("no transparency log entry"));
    }

    #[test]
    fn a_certificate_not_from_fulcio_is_refused() {
        // the Fulcio intermediate in the leaf's place: it is not signed by the intermediate (it is the intermediate)
        let json = edited(|v| v["verificationMaterial"]["certificate"]["rawBytes"] = FULCIO_INTERMEDIATE.into());
        assert!(reason(gh_ok(&json)).contains("not from Sigstore's Fulcio"));
    }

    #[test]
    fn an_envelope_with_two_signatures_is_refused() {
        let json = edited(|v| {
            let s = v["dsseEnvelope"]["signatures"][0].clone();
            v["dsseEnvelope"]["signatures"].as_array_mut().unwrap().push(s);
        });
        assert!(reason(gh_ok(&json)).contains("exactly one signature"));
    }

    #[test]
    fn the_log_entry_must_be_for_this_envelope_and_certificate() {
        let b: Bundle = serde_json::from_slice(&gh_json()).unwrap();
        let entry = &b.verification_material.tlog_entries[0];
        let env = b.dsse_envelope.as_ref().unwrap();
        let (payload, sig) = (B64.decode(&env.payload).unwrap(), B64.decode(&env.signatures[0].sig).unwrap());
        let leaf = B64.decode(&b.verification_material.certificate.as_ref().unwrap().raw_bytes).unwrap();
        assert_eq!(check_logged(entry, &payload, &sig, &leaf), Ok(()));
        assert!(check_logged(entry, b"{}", &sig, &leaf).unwrap_err().contains("another statement"));
        assert!(check_logged(entry, &payload, &sig[1..], &leaf).unwrap_err().contains("another signature"));
        let other = B64.decode(FULCIO_INTERMEDIATE).unwrap();
        assert!(check_logged(entry, &payload, &sig, &other).unwrap_err().contains("another certificate"));
    }

    #[test]
    fn not_a_bundle_is_refused() {
        assert!(reason(gh_ok(b"{}")).contains("not a Sigstore bundle"));
        assert!(reason(gh_ok(&edited(|v| v["mediaType"] = "text/plain".into()))).contains("not a Sigstore bundle"));
    }

    /// The whole way through GitHub's API (tag, attestation list, snappy bundle) for GitHub CLI's release. Needs the network:
    /// `cargo test -- --ignored attest::`.
    #[test]
    #[ignore]
    fn a_published_release_verifies_through_githubs_api() {
        let agent = ureq::AgentBuilder::new().user_agent("PokopiaRecomp-Launcher/test").build();
        let check = |sum: &str| verify_built(&agent, "cli/cli", ".github/workflows/deployment.yml", &["refs/heads/trunk"], "v2.105.0", GH_ASSET, sum);
        assert_eq!(check(GH_SHA256), Ok(()));
        assert!(check(&"0".repeat(64)).is_err(), "a checksum nobody attested has no attestation");
    }

    #[test]
    fn dsse_pae_is_the_spec_encoding() {
        // the DSSE spec's example: DSSEv1 <len type> <type> <len body> <body>
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
    }
}
