//! TLS for the bundled reqwest clients, this crate's and `stack-kms`'s: the
//! platform verifier, wrapped so a chain carrying a compromised CA key is
//! refused.
//!
//! reqwest's `rustls` backend verifies with `rustls-platform-verifier`. On
//! macOS and Windows that is the OS verifier, which applies the OS vendor's
//! distrust lists. On Linux it is webpki over the distro bundle
//! (`rustls-native-certs`) with **no revocation checking**, so a CA whose
//! private key has leaked stays trusted for as long as a root above it is in
//! the bundle — and a cross-signed intermediate chains to a root other than
//! its issuer's. [`client_config`] keeps the platform verifier for every
//! check it makes and adds one of its own after them: no certificate the
//! server presents may carry a public key on the compiled-in blocklist.
//!
//! Only presented certificates are checked, because rustls hands a verifier
//! nothing else. On Linux that covers every chain: webpki builds its path
//! from the presented certificates and the bundle's roots, and never fetches
//! a missing intermediate, so a chain through a blocked intermediate must
//! present it. The macOS and Windows verifiers can fetch or reuse an
//! intermediate the server left out. There the blocklist is a second check,
//! and the OS vendor's own distrust of the same certificates is the one that
//! applies.
//!
//! Native only. On wasm32 reqwest goes through the runtime's `fetch`, and
//! the runtime's TLS applies.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

/// A CA key no chain may carry: the SHA-256 of a certificate's DER-encoded
/// `SubjectPublicKeyInfo` (outer `SEQUENCE` included), the form Node's and
/// Go's blocklists use. Keyed on the key, not the certificate, so one entry
/// covers every certificate issued for that key — an original and its
/// cross-signs alike.
#[derive(Debug)]
pub(crate) struct BlockedSpki {
    /// The CA's common name, for the log line when a chain is refused.
    pub(crate) name: &'static str,
    pub(crate) spki_sha256: [u8; 32],
}

/// The compiled-in blocklist.
///
/// **eMudhra, 2026-10-17.** The private keys of eight eMudhra intermediate
/// CAs were reported compromised. Each exists as an original issued by an
/// emSign root and as a Sectigo cross-sign that chains to Sectigo's "AAA
/// Certificate Services" root, which stays in distro bundles — 16
/// certificates over 8 keys, so 8 entries.
///
/// - Source: <https://emudhra.we-have-a-problem.com/affected-certificates.json>
///   (each intermediate's `spki_sha256` field), read 2026-10-20. Its `sha256`
///   fields are whole-certificate fingerprints and are not used here.
/// - Cross-checked, entry for entry, against the byte arrays in Node's
///   blocklist (nodejs/node#66871, `src/crypto/crypto_context.cc`).
/// - Announcement: <https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE>
///
/// To add an entry from a certificate, hash its key the way this module does:
///
/// ```text
/// openssl x509 -in ca.pem -noout -pubkey | openssl pkey -pubin -outform der | sha256sum
/// ```
pub(crate) const BLOCKED_SPKIS: &[BlockedSpki] = &[
    BlockedSpki {
        name: "EM EV TLS CA - G3B",
        // e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41
        spki_sha256: [
            0xe0, 0x25, 0x4c, 0x7f, 0xcd, 0xc2, 0x65, 0xe2, 0xf0, 0xf8, 0xa4, 0x28, 0xda, 0xbb,
            0x75, 0xab, 0x4a, 0xe0, 0x39, 0xb4, 0x87, 0x2d, 0x62, 0xf5, 0xee, 0x57, 0xf0, 0x87,
            0x7d, 0x5a, 0x8a, 0x41,
        ],
    },
    BlockedSpki {
        name: "EM OV TLS CA - G3B",
        // 43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b
        spki_sha256: [
            0x43, 0xbf, 0xfa, 0x19, 0xd6, 0xef, 0x65, 0x14, 0x51, 0xf6, 0x84, 0x1e, 0x01, 0x99,
            0x31, 0xe9, 0x6f, 0x6f, 0x2e, 0xae, 0xff, 0x28, 0xab, 0x4b, 0x6f, 0x1c, 0xe4, 0x57,
            0x6d, 0xe2, 0x71, 0x7b,
        ],
    },
    BlockedSpki {
        name: "EM DV TLS CA - G3B",
        // ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105
        spki_sha256: [
            0xeb, 0xed, 0x64, 0x75, 0xc2, 0xc2, 0xd8, 0x0f, 0xcb, 0x19, 0x9f, 0x3f, 0xe8, 0xdd,
            0x6e, 0x6b, 0x3c, 0xe6, 0x0b, 0x77, 0xeb, 0x15, 0xd4, 0xe4, 0x2c, 0x3d, 0xec, 0x0c,
            0x6f, 0x5b, 0x51, 0x05,
        ],
    },
    BlockedSpki {
        name: "EM EV TLS CA - G3C",
        // 5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0
        spki_sha256: [
            0x5c, 0x06, 0x60, 0xa2, 0xb1, 0x64, 0x91, 0x0d, 0x8f, 0xf5, 0x89, 0xc1, 0x8e, 0x14,
            0x55, 0x2e, 0x9e, 0x0e, 0xc2, 0x37, 0xdc, 0xef, 0xe2, 0xcb, 0x73, 0x6d, 0x41, 0xa4,
            0x81, 0x1f, 0x81, 0xa0,
        ],
    },
    BlockedSpki {
        name: "EM OV TLS CA - G3C",
        // 63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8
        spki_sha256: [
            0x63, 0xec, 0xef, 0xee, 0x43, 0x1d, 0x49, 0x52, 0x3b, 0xc1, 0x13, 0x6c, 0x4e, 0x72,
            0xd0, 0x20, 0x6a, 0x47, 0x70, 0x86, 0xca, 0xf6, 0x06, 0xcd, 0x5c, 0xf0, 0x25, 0x68,
            0x6c, 0x10, 0x9c, 0xf8,
        ],
    },
    BlockedSpki {
        name: "EM DV TLS CA - G3C",
        // 49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f
        spki_sha256: [
            0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e,
            0x60, 0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e,
            0xa4, 0x34, 0xfe, 0x5f,
        ],
    },
    // The two code-signing CAs cannot issue a TLS server certificate the
    // platform verifier accepts, so for TLS these entries are belt and braces.
    // They are listed because the source lists them and Node blocks them too.
    BlockedSpki {
        name: "EM OV CS CA - G3B",
        // ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6
        spki_sha256: [
            0xec, 0x4f, 0xfa, 0x1a, 0xd0, 0xac, 0x88, 0x08, 0x13, 0x14, 0xb7, 0xaa, 0xff, 0xef,
            0x6a, 0x91, 0xf9, 0x7c, 0xd5, 0x72, 0x91, 0xbb, 0x5b, 0xa6, 0x86, 0xc5, 0x41, 0x5f,
            0x5e, 0xb4, 0xf6, 0xb6,
        ],
    },
    BlockedSpki {
        name: "EM OV CS CA - G3C",
        // 92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30
        spki_sha256: [
            0x92, 0xc0, 0x63, 0xd6, 0x7e, 0x8f, 0x14, 0xdb, 0x71, 0xd2, 0x88, 0xe1, 0x12, 0x66,
            0xff, 0xda, 0xf6, 0x9c, 0xbf, 0x11, 0x5f, 0x7b, 0xab, 0x14, 0xf3, 0xbc, 0x2f, 0x68,
            0xd2, 0x5e, 0x0e, 0x30,
        ],
    },
];

/// The rustls configuration every bundled reqwest client in the stack crates
/// uses, for `reqwest::ClientBuilder::tls_backend_preconfigured`: the
/// platform verifier, wrapped so a chain carrying a key on the compiled-in
/// blocklist is refused as a revoked certificate.
///
/// The crypto provider is chosen the way reqwest chooses it: the process
/// default if one is installed, else aws-lc-rs. A preconfigured backend gets
/// no ALPN from reqwest, so this sets it: `h2` then `http/1.1` when
/// `http2` is true, and only `http/1.1` otherwise. Pass `true` only when the
/// client's reqwest is built with its `http2` feature; a server that
/// negotiates `h2` with a client that cannot speak it fails every request.
///
/// # Errors
///
/// The platform verifier could not be built (on Linux: no CA certificates
/// could be loaded from the system), or the crypto provider supports no safe
/// protocol version. reqwest's own TLS set-up fails in both cases too.
pub fn client_config(http2: bool) -> Result<ClientConfig, Error> {
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let platform = rustls_platform_verifier::Verifier::new(provider.clone())?;
    config_with(provider, Arc::new(platform), BLOCKED_SPKIS, http2)
}

fn config_with(
    provider: Arc<CryptoProvider>,
    inner: Arc<dyn ServerCertVerifier>,
    blocklist: &'static [BlockedSpki],
    http2: bool,
) -> Result<ClientConfig, Error> {
    let verifier = SpkiBlocklistVerifier { inner, blocklist };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols(http2);
    Ok(config)
}

fn alpn_protocols(http2: bool) -> Vec<Vec<u8>> {
    if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    }
}

/// A [`ServerCertVerifier`] that defers every check to `inner` and then
/// refuses a chain in which any presented certificate — the end entity or an
/// intermediate — has a key on `blocklist`.
///
/// Only the presented certificates are checked. rustls passes a verifier
/// nothing else, so an intermediate the platform verifier fetched or took
/// from an OS store is not seen here (see the module docs for where that
/// can happen). Node's and Go's blocklists check the chain their verifier
/// built; rustls gives this wrapper no built chain, so it cannot.
#[derive(Debug)]
struct SpkiBlocklistVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    blocklist: &'static [BlockedSpki],
}

impl SpkiBlocklistVerifier {
    /// The blocklist entry `cert`'s key matches, if any. A certificate that
    /// does not parse is refused rather than passed: its key is unknown.
    fn blocked(&self, cert: &CertificateDer<'_>) -> Result<Option<&'static BlockedSpki>, Error> {
        let parsed = webpki::EndEntityCert::try_from(cert)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let digest: [u8; 32] = Sha256::digest(parsed.subject_public_key_info().as_ref()).into();
        Ok(self
            .blocklist
            .iter()
            .find(|entry| entry.spki_sha256 == digest))
    }
}

impl ServerCertVerifier for SpkiBlocklistVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        for cert in std::iter::once(end_entity).chain(intermediates) {
            if let Some(entry) = self.blocked(cert)? {
                tracing::error!(
                    ca = entry.name,
                    "refused a TLS certificate chain that carries a compromised CA key"
                );
                return Err(Error::InvalidCertificate(CertificateError::Revoked));
            }
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;
    use rustls::RootCertStore;

    // A throwaway three-certificate PKI (P-256, 100-year validity) made with
    // openssl for these tests: root -> intermediate -> leaf for
    // `blocklist.test`. Their SPKI hashes below were computed with openssl
    // (`x509 -pubkey | pkey -pubin -outform der | sha256sum`), independently
    // of the code under test.
    const ROOT: &[u8] = include_bytes!("tls/testdata/root.der");
    const INTERMEDIATE: &[u8] = include_bytes!("tls/testdata/inter.der");
    const LEAF: &[u8] = include_bytes!("tls/testdata/leaf.der");
    const INTERMEDIATE_SPKI: &str =
        "ac260bb40d4d29a8c1d66b7bf8b915093fb6be77758635316383d24d251e8aac";
    const LEAF_SPKI: &str = "eb46a72c0491fed42a0c31f5d98ba0846654610fba79061628467ec58a136553";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn leak_blocklist(entries: Vec<BlockedSpki>) -> &'static [BlockedSpki] {
        Vec::leak(entries)
    }

    fn entry(name: &'static str, spki_hex: &str) -> BlockedSpki {
        BlockedSpki {
            name,
            spki_sha256: unhex(spki_hex),
        }
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// A real webpki verifier that trusts only the test root.
    fn test_root_verifier() -> Arc<dyn ServerCertVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ROOT)).unwrap();
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap()
    }

    fn verifier(
        inner: Arc<dyn ServerCertVerifier>,
        blocklist: &'static [BlockedSpki],
    ) -> SpkiBlocklistVerifier {
        SpkiBlocklistVerifier { inner, blocklist }
    }

    fn verify(
        v: &SpkiBlocklistVerifier,
        intermediates: &[&[u8]],
    ) -> Result<ServerCertVerified, Error> {
        let intermediates: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|der| CertificateDer::from(*der))
            .collect();
        v.verify_server_cert(
            &CertificateDer::from(LEAF),
            &intermediates,
            &ServerName::try_from("blocklist.test").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    /// The blocklist is exactly the eight eMudhra keys, in hex as published
    /// in `affected-certificates.json`. Written out separately from the
    /// byte arrays so a mistyped byte fails here.
    #[test]
    fn the_blocklist_is_exactly_the_published_emudhra_keys() {
        let expected = [
            (
                "EM EV TLS CA - G3B",
                "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
            ),
            (
                "EM OV TLS CA - G3B",
                "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
            ),
            (
                "EM DV TLS CA - G3B",
                "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
            ),
            (
                "EM EV TLS CA - G3C",
                "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
            ),
            (
                "EM OV TLS CA - G3C",
                "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
            ),
            (
                "EM DV TLS CA - G3C",
                "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
            ),
            (
                "EM OV CS CA - G3B",
                "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
            ),
            (
                "EM OV CS CA - G3C",
                "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
            ),
        ];
        let actual: Vec<(&str, String)> = BLOCKED_SPKIS
            .iter()
            .map(|e| (e.name, hex(&e.spki_sha256)))
            .collect();
        let expected: Vec<(&str, String)> = expected
            .iter()
            .map(|(name, spki)| (*name, (*spki).to_owned()))
            .collect();
        assert_eq!(actual, expected);
    }

    /// The hash is over the whole DER `SubjectPublicKeyInfo`, as openssl
    /// computes it — the form the published hashes take.
    #[test]
    fn a_key_is_hashed_as_openssl_hashes_it() {
        let blocklist = leak_blocklist(vec![
            entry("leaf", LEAF_SPKI),
            entry("intermediate", INTERMEDIATE_SPKI),
        ]);
        let v = verifier(test_root_verifier(), blocklist);
        let leaf = v.blocked(&CertificateDer::from(LEAF)).unwrap().unwrap();
        assert_eq!(leaf.name, "leaf");
        let intermediate = v
            .blocked(&CertificateDer::from(INTERMEDIATE))
            .unwrap()
            .unwrap();
        assert_eq!(intermediate.name, "intermediate");
        assert!(v.blocked(&CertificateDer::from(ROOT)).unwrap().is_none());
    }

    #[test]
    fn a_chain_the_inner_verifier_accepts_and_nothing_blocks_is_accepted() {
        let v = verifier(test_root_verifier(), BLOCKED_SPKIS);
        verify(&v, &[INTERMEDIATE]).unwrap();
    }

    #[test]
    fn a_blocked_intermediate_is_refused_as_revoked() {
        let blocklist = leak_blocklist(vec![entry("intermediate", INTERMEDIATE_SPKI)]);
        let v = verifier(test_root_verifier(), blocklist);
        assert_eq!(
            verify(&v, &[INTERMEDIATE]).unwrap_err(),
            Error::InvalidCertificate(CertificateError::Revoked)
        );
    }

    #[test]
    fn a_blocked_end_entity_is_refused_as_revoked() {
        let blocklist = leak_blocklist(vec![entry("leaf", LEAF_SPKI)]);
        let v = verifier(test_root_verifier(), blocklist);
        assert_eq!(
            verify(&v, &[INTERMEDIATE]).unwrap_err(),
            Error::InvalidCertificate(CertificateError::Revoked)
        );
    }

    /// A blocked key anywhere in the presented intermediates counts, not
    /// only the first.
    #[test]
    fn a_blocked_key_after_the_first_intermediate_is_refused() {
        let blocklist = leak_blocklist(vec![entry("intermediate", INTERMEDIATE_SPKI)]);
        let v = verifier(Arc::new(Inner::accepting()), blocklist);
        assert_eq!(
            verify(&v, &[ROOT, INTERMEDIATE]).unwrap_err(),
            Error::InvalidCertificate(CertificateError::Revoked)
        );
    }

    /// The inner verifier runs first and its refusal stands: the blocklist
    /// only ever narrows what it accepts.
    #[test]
    fn the_inner_verifiers_refusal_is_returned() {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(LEAF)).unwrap();
        // Trusts a root the chain does not lead to.
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap();
        let v = verifier(inner, BLOCKED_SPKIS);
        assert_eq!(
            verify(&v, &[INTERMEDIATE]).unwrap_err(),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
    }

    #[test]
    fn a_certificate_that_does_not_parse_is_refused() {
        let v = verifier(Arc::new(Inner::accepting()), BLOCKED_SPKIS);
        assert_eq!(
            verify(&v, &[b"not a certificate"]).unwrap_err(),
            Error::InvalidCertificate(CertificateError::BadEncoding)
        );
    }

    /// Everything but the chain check is the inner verifier's answer. (The
    /// two handshake-signature checks are delegated the same way; rustls
    /// gives a test no way to build the `DigitallySignedStruct` they take.)
    #[test]
    fn the_other_checks_are_delegated() {
        let v = verifier(Arc::new(Inner::accepting()), BLOCKED_SPKIS);
        assert_eq!(
            v.supported_verify_schemes(),
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256
            ]
        );
        assert!(v.requires_raw_public_keys());
        let hints: Vec<&[u8]> = v
            .root_hint_subjects()
            .unwrap()
            .iter()
            .map(DistinguishedName::as_ref)
            .collect();
        assert_eq!(hints, vec![b"hint".as_slice()]);

        // And the opposite answers, so neither is a constant.
        let v = verifier(
            Arc::new(Inner {
                raw_public_keys: false,
                hints: None,
            }),
            BLOCKED_SPKIS,
        );
        assert!(!v.requires_raw_public_keys());
        assert!(v.root_hint_subjects().is_none());
    }

    #[test]
    fn alpn_follows_http2() {
        let inner: Arc<dyn ServerCertVerifier> = Arc::new(Inner::accepting());
        let h2 = config_with(provider(), inner.clone(), BLOCKED_SPKIS, true).unwrap();
        assert_eq!(
            h2.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let h1 = config_with(provider(), inner, BLOCKED_SPKIS, false).unwrap();
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// The config is one reqwest recognises: a rustls version reqwest does
    /// not share makes `tls_backend_preconfigured` an unknown backend, and
    /// `build` fails.
    #[test]
    fn reqwest_accepts_the_config() {
        for http2 in [false, true] {
            let config = client_config(http2).unwrap();
            reqwest::Client::builder()
                .tls_backend_preconfigured(config)
                .build()
                .unwrap();
        }
    }

    /// An inner verifier whose every answer is recognisable.
    #[derive(Debug)]
    struct Inner {
        raw_public_keys: bool,
        hints: Option<Vec<DistinguishedName>>,
    }

    impl Inner {
        fn accepting() -> Self {
            Self {
                raw_public_keys: true,
                hints: Some(vec![DistinguishedName::from(b"hint".to_vec())]),
            }
        }
    }

    impl ServerCertVerifier for Inner {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("tls12".into()))
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("tls13".into()))
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }

        fn requires_raw_public_keys(&self) -> bool {
            self.raw_public_keys
        }

        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            self.hints.as_deref()
        }
    }
}
