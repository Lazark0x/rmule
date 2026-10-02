//! eMuleAI's pinned QUIC parameters, reproduced exactly where they are
//! observable and deliberately not where they are not.
//!
//! Every value here is on the wire or decides whether a handshake completes:
//! the ALPN, TLS 1.3 only, the cipher and group order, a self-signed RSA-2048
//! certificate, and **no verification at all** on either side. That last one is
//! not laxity rmule inherited by accident — it is why the 37-byte `EAQN1` proof
//! exists. TLS here proves that somebody completed a handshake; the proof is
//! what names them.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_RSA_SHA256};
use rsa::pkcs8::EncodePrivateKey;
use rsa::{RsaPrivateKey, rand_core::OsRng};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// The ALPN identifier, `GNUTLS_ALPN_MANDATORY` on eMuleAI's side — a peer that
/// does not offer it gets no handshake, which is the point: it keeps a NAT-T
/// QUIC connection from being confused with any other QUIC on the wire.
pub const NATT_QUIC_ALPN: &[u8] = b"ed2k-ai-natt-quic-v1";

/// The SNI a dialer sends. eMuleAI's constant, kept literally: a conforming
/// responder may select a certificate by it, and a different name would be a
/// different request.
pub const NATT_QUIC_SNI: &str = "emuleai-natt";

/// The certificate's subject common name.
///
/// **Deliberately not eMuleAI's `eMuleAI QUIC NAT-T`.** Nothing verifies this
/// field — there is no verifier on either side — so copying it would buy no
/// interoperability and would put a false vendor claim in a certificate rmule
/// signed. [`NATT_QUIC_SNI`] is in the certificate's SAN list instead, which is
/// the field a conforming peer would actually match.
pub const NATT_QUIC_COMMON_NAME: &str = "rmule QUIC NAT-T";

/// eMuleAI's certificate key size.
const NATT_QUIC_RSA_BITS: usize = 2048;

/// The crypto provider: `ring`, with eMuleAI's cipher and group order.
///
/// Two named divergences, both forced and both harmless:
///
/// - **AES-128-CCM is absent.** eMuleAI lists it fourth; `ring` implements no
///   CCM suite at all. TLS 1.3 requires `TLS_AES_128_GCM_SHA256` of every
///   implementation, and that is first in both orders, so no handshake can turn
///   on the missing suite.
/// - **Group order is expressed by what `ring` offers.** SECP256R1, X25519 and
///   SECP384R1 are all present and are ordered as eMuleAI orders them.
fn provider() -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    let order = [
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    let cipher_suites = order
        .iter()
        .filter_map(|wanted| {
            base.cipher_suites
                .iter()
                .find(|suite| suite.suite() == *wanted)
                .copied()
        })
        .collect();
    let group_order = [
        rustls::NamedGroup::secp256r1,
        rustls::NamedGroup::X25519,
        rustls::NamedGroup::secp384r1,
    ];
    let kx_groups = group_order
        .iter()
        .filter_map(|wanted| {
            base.kx_groups
                .iter()
                .find(|group| group.name() == *wanted)
                .copied()
        })
        .collect();
    CryptoProvider {
        cipher_suites,
        kx_groups,
        ..base
    }
}

/// A freshly generated self-signed RSA-2048 identity for this process.
///
/// Per process rather than per connection: generating a 2048-bit RSA key costs
/// real time, and the certificate carries no identity anybody checks — the
/// identity is the `EAQN1` proof, which is per connection.
pub struct NattQuicIdentity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl NattQuicIdentity {
    /// Generate one.
    ///
    /// # Errors
    /// [`QuicTlsError`] when key generation or certificate writing failed —
    /// neither is expected, and both are reported rather than panicked because
    /// an entropy failure is a real runtime condition.
    pub fn generate() -> Result<Self, QuicTlsError> {
        let private = RsaPrivateKey::new(&mut OsRng, NATT_QUIC_RSA_BITS)
            .map_err(|_| QuicTlsError::KeyGeneration)?;
        let pkcs8 = private
            .to_pkcs8_der()
            .map_err(|_| QuicTlsError::KeyGeneration)?;
        let key = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
        // `ring` cannot *generate* an RSA key, only sign with one, which is
        // why the key comes from the `rsa` crate already in the tree and only
        // the certificate writing is rcgen's.
        let signing_key = KeyPair::from_pkcs8_der_and_sign_algo(&key, &PKCS_RSA_SHA256)
            .map_err(|source| QuicTlsError::Certificate { source })?;
        let mut params = CertificateParams::new(vec![NATT_QUIC_SNI.to_string()])
            .map_err(|source| QuicTlsError::Certificate { source })?;
        params
            .distinguished_name
            .push(DnType::CommonName, NATT_QUIC_COMMON_NAME);
        let certificate = params
            .self_signed(&signing_key)
            .map_err(|source| QuicTlsError::Certificate { source })?;
        Ok(Self {
            certificate: certificate.der().clone(),
            key,
        })
    }

    /// The certificate this endpoint presents.
    #[must_use]
    pub const fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// The QUIC server parameters: TLS 1.3, the pinned ALPN, this certificate,
    /// and no client authentication (there is nothing to authenticate against).
    ///
    /// # Errors
    /// [`QuicTlsError`] when rustls refused the configuration.
    pub fn server_config(&self) -> Result<quinn::ServerConfig, QuicTlsError> {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|source| QuicTlsError::Rustls { source })?
            .with_no_client_auth()
            .with_single_cert(
                vec![self.certificate.clone()],
                PrivateKeyDer::Pkcs8(self.key.clone_key()),
            )
            .map_err(|source| QuicTlsError::Rustls { source })?;
        tls.alpn_protocols = vec![NATT_QUIC_ALPN.to_vec()];
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|_| QuicTlsError::NotTls13)?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
    }

    /// The QUIC client parameters: TLS 1.3, the pinned ALPN, and a verifier
    /// that accepts every certificate.
    ///
    /// # Errors
    /// [`QuicTlsError`] when rustls refused the configuration.
    pub fn client_config(&self) -> Result<quinn::ClientConfig, QuicTlsError> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|source| QuicTlsError::Rustls { source })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        tls.alpn_protocols = vec![NATT_QUIC_ALPN.to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|_| QuicTlsError::NotTls13)?;
        Ok(quinn::ClientConfig::new(Arc::new(quic)))
    }
}

/// Why the QUIC TLS parameters could not be built.
#[derive(Debug, thiserror::Error)]
pub enum QuicTlsError {
    /// RSA key generation failed — an entropy failure, not a configuration one.
    #[error("could not generate the NAT-T QUIC RSA-2048 key")]
    KeyGeneration,

    /// The self-signed certificate could not be written.
    #[error("could not write the NAT-T QUIC certificate: {source}")]
    Certificate {
        /// What rcgen reported.
        source: rcgen::Error,
    },

    /// rustls refused the configuration.
    #[error("rustls refused the NAT-T QUIC configuration: {source}")]
    Rustls {
        /// What rustls reported.
        source: rustls::Error,
    },

    /// The configuration was not TLS 1.3 only. Unreachable while the builder
    /// above pins the version list, and reported rather than unwrapped so a
    /// future edit cannot turn it into a panic.
    #[error("the NAT-T QUIC configuration is not TLS 1.3 only")]
    NotTls13,
}

/// The verifier eMuleAI does not install: no trust anchors, no name check, no
/// revocation. Reproduced because it is what the counterparty does, and because
/// the alternative — refusing every self-signed peer — would make the dialect
/// unspeakable.
///
/// What still holds the connection together is the `EAQN1` proof, which no TLS
/// setting could have provided: a certificate nobody vouches for says nothing
/// about a **User Hash**, and the user hash is the only identity eD2k has.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is not offered, so this is unreachable; asserting rather
        // than erroring keeps the two signature paths consistent.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AES-128-GCM leads, which is the suite TLS 1.3 requires of everyone, and
    /// the group order is eMuleAI's.
    #[test]
    fn the_cipher_and_group_order_is_emuleais_minus_what_ring_lacks() {
        let provider = provider();
        let suites: Vec<_> = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect();
        assert_eq!(
            suites,
            vec![
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ]
        );
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            vec![
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::secp384r1,
            ]
        );
    }

    /// The identity builds both configurations, and the certificate carries
    /// the SNI as a SAN so a conforming peer that *does* match names finds it.
    #[test]
    fn the_identity_builds_a_client_and_a_server_configuration() {
        let identity = NattQuicIdentity::generate().expect("RSA-2048 and a self-signed cert");
        identity.server_config().expect("a TLS 1.3 server config");
        identity.client_config().expect("a TLS 1.3 client config");
        assert!(!identity.certificate().is_empty());
    }
}
