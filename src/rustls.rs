#![cfg(feature = "__rustls-used")]

/// Call this before using rustls.
#[doc(hidden)]
#[allow(clippy::result_unit_err)]
pub fn install_default_crypto_provider_if_necessary() -> Result<(), ()> {
    #[cfg(feature = "__install-crypto-provider")]
    {
        static INSTALL: std::sync::OnceLock<Result<(), ()>> = std::sync::OnceLock::new();

        let result = INSTALL.get_or_init(|| {
            // A crypto provider is already installed.
            if rustls::crypto::CryptoProvider::get_default().is_some() {
                return Ok(());
            }

            #[cfg(feature = "aws-lc-rs")]
            {
                rustls::crypto::aws_lc_rs::default_provider()
                    .install_default()
                    .map_err(|_| ())
            }

            #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
            {
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .map_err(|_| ())
            }
        });

        *result
    }

    #[cfg(not(feature = "__install-crypto-provider"))]
    {
        Ok(())
    }
}

/// Configures the client to verify server certificates with the operating system verifier.
///
/// `rustls-native-certs` has no iOS loader and yields an empty root store there.
/// That store rejects every server certificate.
// UNTESTED: system trust on iOS. CAs installed by MDM or a user profile must be trusted,
// while untrusted and wrong-host certificates must be rejected. A KDC proxy behind an
// untrusted certificate would otherwise silently fall back to NTLM. When changing this code,
// repeat on a device: reach `/jet/KdcProxy` through a Gateway, then retry with an untrusted certificate.
#[cfg(all(feature = "network_client", target_os = "ios"))]
pub(crate) fn load_native_certs(
    builder: reqwest::blocking::ClientBuilder,
) -> crate::Result<reqwest::blocking::ClientBuilder> {
    use rustls_platform_verifier::ConfigVerifierExt as _;

    let config = rustls::ClientConfig::with_platform_verifier().map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::NoAuthenticatingAuthority,
            format!("Failed to create the platform certificate verifier: {error}"),
        )
    })?;

    Ok(builder.use_preconfigured_tls(config))
}

#[cfg(all(feature = "network_client", not(target_os = "ios")))]
pub(crate) fn load_native_certs(
    builder: reqwest::blocking::ClientBuilder,
) -> crate::Result<reqwest::blocking::ClientBuilder> {
    #[cfg(feature = "aws-lc-rs")]
    {
        let mut builder = builder;

        let result = rustls_native_certs::load_native_certs();

        for error in result.errors {
            debug!(%error, "native root CA certificate loading error");
        }

        for cert in result.certs {
            // Continue on parsing errors, as native stores often include ancient or syntactically
            // invalid certificates, like root certificates without any X509 extensions.
            // Inspiration: https://github.com/rustls/rustls/blob/633bf4ba9d9521a95f68766d04c22e2b01e68318/rustls/src/anchors.rs#L105-L112
            match reqwest::Certificate::from_der(&cert) {
                Ok(cert) => builder = builder.add_root_certificate(cert),
                Err(error) => {
                    debug!(%error, "failed to parse native certificate");
                }
            };
        }

        Ok(builder)
    }

    // We enable the rustls-tls-native-roots feature of reqwest when ring is used.
    #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
    {
        Ok(builder)
    }
}
