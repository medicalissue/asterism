//! The enrollment wire, checked against the vectors the Worker checks.
//!
//! `tests/fixtures/enrollment-vectors.json` is a byte-identical copy of
//! `tests/fixtures/enrollment-vectors.json` in `medicalissue/asterism-site`,
//! which is the source of truth. Both suites read the same bytes, so a change
//! to the signed message, the challenge encoding, or the generation
//! commitment fails on both sides of the wire rather than in production.
//!
//! The contract itself is `docs/hosted-coordination.md`, section "Device
//! enrollment and presence".

use asterism_coordinator::{
    enrollment_signed_message, enrollment_proof, sign_enrollment_challenge, AccountBinding,
    AuthorizationProvider, Coordinator, DiscoveryConfig, EnrollmentProof, VerifiedIdentity,
    VerifiedIdentitySource, DEVICE_AUTHORIZATION_PROTOCOL,
};
use asterism_mesh::DeviceIdentity;

const VECTORS: &str = include_str!("fixtures/enrollment-vectors.json");

#[derive(serde::Deserialize)]
struct Vectors {
    enrollment_domain_hex: String,
    generation_domain_hex: String,
    valid: Vec<Vector>,
    invalid: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    device_id: String,
    generation: String,
    challenge: String,
    message_hex: String,
    signature: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("the shared fixture parses")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> Vec<u8> {
    (0..value.len() / 2)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn the_domain_separators_are_the_bytes_both_sides_hash() {
    let vectors = vectors();
    assert_eq!(
        String::from_utf8(from_hex(&vectors.enrollment_domain_hex)).unwrap(),
        "asterism.coordinator/enroll/1\0"
    );
    assert_eq!(
        String::from_utf8(from_hex(&vectors.generation_domain_hex)).unwrap(),
        "asterism.coordinator/enroll-generation/1\0"
    );
}

#[test]
fn every_shared_vector_verifies_against_its_device_key() {
    let vectors = vectors();
    assert!(!vectors.valid.is_empty());
    for vector in &vectors.valid {
        assert_eq!(vector.device_id.len(), 64, "{}", vector.name);
        assert_eq!(vector.challenge.len(), 86, "{}", vector.name);
        assert_eq!(vector.signature.len(), 86, "{}", vector.name);
        assert_eq!(vector.generation.len(), 43, "{}", vector.name);

        // The signed message is the whole cross-implementation contract: the
        // domain, the commitment to the account generation, and the nonce.
        let message = enrollment_signed_message(&vector.challenge).expect(&vector.name);
        assert_eq!(hex(&message), vector.message_hex, "{}", vector.name);
        assert_eq!(message.len(), 30 + 64, "{}", vector.name);

        let proof = EnrollmentProof::from_tokens(&vector.device_id, &vector.challenge, &vector.signature)
            .expect(&vector.name);
        assert!(
            proof.device_id.verify(&message, &proof.signature),
            "{} did not verify",
            vector.name
        );
    }
}

#[test]
fn a_tampered_signature_and_a_stale_generation_both_fail() {
    let vectors = vectors();
    assert_eq!(vectors.invalid.len(), 2);
    for vector in &vectors.invalid {
        let message = enrollment_signed_message(&vector.challenge).expect(&vector.name);
        let verified = EnrollmentProof::from_tokens(&vector.device_id, &vector.challenge, &vector.signature)
            .map(|proof| proof.device_id.verify(&message, &proof.signature))
            .unwrap_or(false);
        match vector.name.as_str() {
            // A flipped bit is refused by the signature check itself.
            "tampered-signature" => assert!(!verified, "{} verified", vector.name),
            // A challenge minted for another generation still carries a valid
            // signature over its own bytes; what refuses it is the generation
            // commitment, which the service compares, not the device.
            "wrong-generation" => assert!(verified, "{} should be self-consistent", vector.name),
            other => panic!("unexpected invalid vector {other}"),
        }
    }
}

#[test]
fn signing_a_challenge_produces_the_wire_signature_the_proof_carries() {
    let identity = DeviceIdentity::generate();
    let mut service = Coordinator::new([7; 32]);
    let binding = service.sign_in_identity(identity_for("subject")).unwrap();
    let challenge = service.begin_enrollment(&binding).unwrap();
    let token = challenge.token();
    assert_eq!(token.len(), 86);

    let encoded = sign_enrollment_challenge(&identity, &token).unwrap();
    let parsed = EnrollmentProof::from_tokens(&identity.device_id().to_string(), &token, &encoded).unwrap();
    let direct = enrollment_proof(&identity, challenge);
    assert_eq!(parsed.signature.to_bytes(), direct.signature.to_bytes());

    let device = service
        .enroll(&binding, parsed, DiscoveryConfig::default())
        .unwrap();
    assert_eq!(device.device_id, identity.device_id().to_string());
    // Enrollment publishes nothing about where the device is until the device
    // says so itself.
    assert!(device.endpoints.is_empty());
}

#[test]
fn a_challenge_is_single_use_and_bound_to_the_account_that_asked_for_it() {
    let identity = DeviceIdentity::generate();
    let mut service = Coordinator::new([9; 32]);
    let mine = service.sign_in_identity(identity_for("mine")).unwrap();
    let theirs = service.sign_in_identity(identity_for("theirs")).unwrap();

    let challenge = service.begin_enrollment(&mine).unwrap();
    let token = challenge.token();
    let signature = sign_enrollment_challenge(&identity, &token).unwrap();
    let device_id = identity.device_id().to_string();
    let proof = || EnrollmentProof::from_tokens(&device_id, &token, &signature).unwrap();

    // Another account cannot spend it: the commitment names a generation.
    assert!(service
        .enroll(&theirs, proof(), DiscoveryConfig::default())
        .is_err());
    assert!(service
        .enroll(&mine, proof(), DiscoveryConfig::default())
        .is_ok());
    // And it is gone once spent.
    assert!(service
        .enroll(&mine, proof(), DiscoveryConfig::default())
        .is_err());
    let _: &AccountBinding = &mine;
}

#[test]
fn published_hints_replace_rather_than_accumulate() {
    let identity = DeviceIdentity::generate();
    let mut service = Coordinator::new([3; 32]);
    let binding = service.sign_in_identity(identity_for("hints")).unwrap();
    let challenge = service.begin_enrollment(&binding).unwrap();
    service
        .enroll(
            &binding,
            enrollment_proof(&identity, challenge),
            DiscoveryConfig::default(),
        )
        .unwrap();

    let first = asterism_coordinator::EndpointHints {
        addrs: vec!["192.0.2.1:41641".into()],
        relay_url: Some("https://relay.example".into()),
    };
    let device = service
        .publish_endpoints(&binding, &identity.device_id(), first)
        .unwrap();
    assert_eq!(device.endpoints.addrs, vec!["192.0.2.1:41641".to_owned()]);

    let second = asterism_coordinator::EndpointHints {
        addrs: vec!["198.51.100.7:41641".into()],
        relay_url: None,
    };
    let device = service
        .publish_endpoints(&binding, &identity.device_id(), second)
        .unwrap();
    // Where it is now, never where it has been.
    assert_eq!(device.endpoints.addrs, vec!["198.51.100.7:41641".to_owned()]);
    assert!(device.endpoints.relay_url.is_none());

    // Anything that is not a literal socket address is refused outright.
    assert!(service
        .publish_endpoints(
            &binding,
            &identity.device_id(),
            asterism_coordinator::EndpointHints {
                addrs: vec!["laptop.local:41641".into()],
                relay_url: None,
            },
        )
        .is_err());
}

#[test]
fn the_device_authorization_protocol_string_did_not_move() {
    assert_eq!(
        DEVICE_AUTHORIZATION_PROTOCOL,
        "asterism-device-authorization/1"
    );
    assert_eq!(
        serde_json::to_string(&AuthorizationProvider::Google).unwrap(),
        "\"google\""
    );
}

struct Edge(&'static str);

impl VerifiedIdentitySource for Edge {
    fn verify_session(&self, _: &str) -> anyhow::Result<VerifiedIdentity> {
        VerifiedIdentity::new("https://asterism.run", self.0)
    }
}

fn identity_for(subject: &'static str) -> VerifiedIdentity {
    Edge(subject).verify_session("bearer").unwrap()
}
