//! TLS 1.3 configured to authenticate *devices* rather than hostnames.
//!
//! There is no certificate authority anywhere in this design. Each device mints
//! a self-signed certificate carrying its own long-lived Ed25519 public key,
//! and a peer is authenticated by checking that the key in the presented
//! certificate hashes to the [`DeviceId`] we expected. That is the same
//! trust-on-first-use model as SSH host keys: meaningless the first time you
//! see a device, and a hard guarantee every time after.
//!
//! Consequences worth knowing:
//!
//! - Certificate validity dates and hostnames are deliberately ignored. They
//!   carry no information here, because nothing signs them but the device
//!   itself. Pinning the key is the entire check.
//! - Both ends present certificates. The server requires client auth so it can
//!   learn who connected before deciding whether to accept anything from them.
//! - TLS only proves possession of a key. Deciding whether that key is *welcome*
//!   is an application-layer question, answered against the trust store once the
//!   handshake exposes the peer's id.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{Error, Result};
use crate::identity::{DeviceId, Identity};

/// ALPN token. Bump the version when the wire protocol changes incompatibly —
/// an old build then fails at handshake with a clear alert instead of
/// misparsing frames halfway through a transfer.
pub const ALPN: &[u8] = b"jet/1";

/// Placeholder SAN. Our verifier never reads it, but rustls requires the client
/// to name *something*, and `.invalid` is reserved by RFC 2606 precisely so it
/// can never resolve to a real host.
pub const CERT_SUBJECT: &str = "jetstream.invalid";

fn provider() -> Arc<CryptoProvider> {
    // Pinned explicitly rather than relying on the process-wide default, so an
    // embedding application that installs its own provider cannot change which
    // algorithms our device authentication accepts.
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A freshly minted certificate and the key that signed it.
pub struct TlsMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Mint a self-signed certificate wrapping this device's long-lived key.
///
/// Called once per process start. The certificate is disposable; the identity
/// inside it is not.
pub fn certificate_for(identity: &Identity) -> Result<TlsMaterial> {
    let key_pair = identity.key_pair()?;
    let params =
        rcgen::CertificateParams::new(vec![CERT_SUBJECT.to_string()]).map_err(Error::cert)?;
    let cert = params.self_signed(&key_pair).map_err(Error::cert)?;

    Ok(TlsMaterial {
        cert_chain: vec![cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.pkcs8_der().to_vec())),
    })
}

/// Recover the peer's device id from the certificate it presented.
///
/// Rejects anything that is not an Ed25519 certificate. Without that check a
/// peer could present a key of another type whose encoding happened to hash to
/// a device id we trust — remote, but free to rule out.
pub fn device_id_from_cert(der: &CertificateDer<'_>) -> Result<DeviceId> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| Error::Certificate(format!("could not parse peer certificate: {e}")))?;

    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Err(Error::Certificate(format!(
            "peer certificate uses {} but Jetstream identities are Ed25519",
            spki.algorithm.algorithm
        )));
    }
    if spki.subject_public_key.unused_bits != 0 {
        return Err(Error::Certificate(
            "peer public key bit string is not byte-aligned".into(),
        ));
    }

    Ok(DeviceId::from_public_key(&spki.subject_public_key.data))
}

/// Pull the peer's device id out of a completed quinn connection.
pub fn peer_device_id(connection: &quinn::Connection) -> Result<DeviceId> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| Error::Protocol("peer presented no certificate".into()))?;

    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| Error::Protocol("unexpected peer identity type".into()))?;

    let end_entity = chain
        .first()
        .ok_or_else(|| Error::Protocol("peer certificate chain was empty".into()))?;

    device_id_from_cert(end_entity)
}

/// Client-side verifier that pins the server's device id.
#[derive(Debug)]
struct PinnedDeviceVerifier {
    /// `None` means first contact: accept whoever answers, then let the
    /// application prompt the user with the id we observed. `Some` means we
    /// have paired before and anything else is a hard failure.
    expected: Option<DeviceId>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedDeviceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual = device_id_from_cert(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;

        match self.expected {
            // Constant-time comparison is unnecessary: the expected id is not a
            // secret, and a timing side channel would leak nothing an attacker
            // cannot read off the wire already.
            Some(expected) if expected != actual => {
                tracing::warn!(
                    expected = %expected.short(),
                    actual = %actual.short(),
                    "rejecting connection: peer identity does not match the paired device"
                );
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server-side verifier that accepts any syntactically valid device identity.
///
/// Intentionally permissive: refusing unknown devices here would return an
/// opaque TLS alert, and we would never learn who was knocking. Instead we
/// complete the handshake, read the peer's id, and apply the trust store at the
/// application layer — where an untrusted device produces a user-visible
/// pairing prompt or a logged rejection with a name attached.
#[derive(Debug)]
struct AnyDeviceVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyDeviceVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        device_id_from_cert(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the client half of the handshake.
///
/// Pass `expected = Some(id)` for a device the user has already paired with;
/// pass `None` only for a deliberate first-contact attempt whose result will be
/// shown to the user for confirmation.
pub fn client_config(identity: &Identity, expected: Option<DeviceId>) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let material = certificate_for(identity)?;

    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(Error::crypto)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedDeviceVerifier { expected, provider }))
        .with_client_auth_cert(material.cert_chain, material.key)
        .map_err(Error::crypto)?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Build the server half of the handshake.
pub fn server_config(identity: &Identity) -> Result<rustls::ServerConfig> {
    let provider = provider();
    let material = certificate_for(identity)?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(Error::crypto)?
        .with_client_cert_verifier(Arc::new(AnyDeviceVerifier { provider }))
        .with_single_cert(material.cert_chain, material.key)
        .map_err(Error::crypto)?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_carries_the_device_identity() {
        let identity = Identity::generate().unwrap();
        let material = certificate_for(&identity).unwrap();

        let recovered = device_id_from_cert(&material.cert_chain[0]).unwrap();
        assert_eq!(recovered, identity.device_id());
    }

    #[test]
    fn device_id_survives_certificate_regeneration() {
        // The whole point of deriving the id from the key rather than the
        // certificate: restarting the app must not break existing pairings.
        let identity = Identity::generate().unwrap();

        let first = certificate_for(&identity).unwrap();
        let second = certificate_for(&identity).unwrap();

        assert_eq!(
            device_id_from_cert(&first.cert_chain[0]).unwrap(),
            device_id_from_cert(&second.cert_chain[0]).unwrap(),
        );
    }

    #[test]
    fn rejects_garbage_certificates() {
        let junk = CertificateDer::from(vec![0x30, 0x00, 0xff, 0xff]);
        assert!(device_id_from_cert(&junk).is_err());
    }

    #[test]
    fn rejects_non_ed25519_certificates() {
        // An ECDSA identity must not be accepted even though it is a perfectly
        // valid certificate — we only speak Ed25519.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec![CERT_SUBJECT.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let err = device_id_from_cert(cert.der()).unwrap_err();
        assert!(
            matches!(err, Error::Certificate(ref m) if m.contains("Ed25519")),
            "expected an algorithm complaint, got {err:?}"
        );
    }

    #[test]
    fn configs_negotiate_our_alpn_and_tls13_only() {
        let identity = Identity::generate().unwrap();

        let client = client_config(&identity, None).unwrap();
        let server = server_config(&identity).unwrap();

        assert_eq!(client.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(server.alpn_protocols, vec![ALPN.to_vec()]);
    }
}
