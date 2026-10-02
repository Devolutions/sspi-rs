/// Call this before using rustls.
#[doc(hidden)]
#[allow(clippy::result_unit_err)]
pub fn install_default_crypto_provider_if_necessary() -> Result<(), ()> {
    #[cfg(feature = "__install-crypto-provider")]
    {
        static INSTALL: std::sync::OnceLock<Result<(), ()>> = std::sync::OnceLock::new();

        let result = INSTALL.get_or_init(|| {
            if let Some(_provider) = rustls::crypto::CryptoProvider::get_default() {
                #[cfg(feature = "fips")]
                return _provider.fips().then_some(()).ok_or(());

                #[cfg(not(feature = "fips"))]
                return Ok(());
            }

            #[cfg(feature = "fips")]
            {
                let provider = rustls::crypto::default_fips_provider();
                if !provider.fips() {
                    return Err(());
                }

                provider.install_default().map_err(|_| ())
            }

            #[cfg(all(not(feature = "fips"), feature = "aws-lc-rs"))]
            {
                rustls::crypto::aws_lc_rs::default_provider()
                    .install_default()
                    .map_err(|_| ())
            }

            #[cfg(all(not(feature = "fips"), not(feature = "aws-lc-rs"), feature = "ring"))]
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

#[cfg(feature = "network_client")]
pub(crate) fn load_native_certs(builder: reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder {
    #[cfg(any(feature = "aws-lc-rs", feature = "fips"))]
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

        builder
    }

    // We enable the rustls-tls-native-roots feature of reqwest when ring is used.
    #[cfg(all(not(feature = "fips"), not(feature = "aws-lc-rs"), feature = "ring"))]
    {
        builder
    }
}

#[cfg(all(test, feature = "fips"))]
mod tests {
    use std::sync::Arc;

    const NON_FIPS_PROVIDER_CHILD: &str = "SSPI_TEST_NON_FIPS_PROVIDER_CHILD";

    #[derive(Debug)]
    struct NonFipsSecureRandom(&'static dyn rustls::crypto::SecureRandom);

    impl rustls::crypto::SecureRandom for NonFipsSecureRandom {
        fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            self.0.fill(buf)
        }
    }

    #[test]
    fn fips_provider_and_config_report_fips() {
        super::install_default_crypto_provider_if_necessary().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().unwrap().fips());

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::default_fips_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(config.fips());
    }

    #[test]
    fn fips_profile_rejects_preinstalled_non_fips_provider() {
        if std::env::var_os(NON_FIPS_PROVIDER_CHILD).is_some() {
            let mut provider = rustls::crypto::default_fips_provider();
            provider.secure_random = Box::leak(Box::new(NonFipsSecureRandom(provider.secure_random)));
            assert!(!provider.fips());
            provider.install_default().unwrap();

            assert_eq!(super::install_default_crypto_provider_if_necessary(), Err(()));
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rustls::tests::fips_profile_rejects_preinstalled_non_fips_provider",
                "--nocapture",
            ])
            .env(NON_FIPS_PROVIDER_CHILD, "1")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "isolated test process failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
