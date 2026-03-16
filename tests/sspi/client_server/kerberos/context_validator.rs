use sspi::NegotiatedProtocol;
use sspi::credssp::SspiContext;

/// Helper-trait to implement SSPI context validation in tests.
///
/// _Note_: this trait is not complete and may be extended in the future when needed.
pub(super) trait SspiContextValidator {
    /// Validates the client SSPI context after the provided number of iterations.
    fn validate_client(&mut self, step: usize, client: &SspiContext);
}

/// Empty validator that does not perform any validation.
pub(super) struct EmptySspiContextValidator;

impl SspiContextValidator for EmptySspiContextValidator {
    fn validate_client(&mut self, _step: usize, _client: &SspiContext) {}
}

/// Performs additional SPNEGO context validation for Kerberos over SPNEGO tests.
pub(super) struct SpnegoKerberosContextValidator {
    pub u2u: bool,
}

impl SspiContextValidator for SpnegoKerberosContextValidator {
    fn validate_client(&mut self, step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        assert!(matches!(
            negotiate.negotiated_protocol(),
            NegotiatedProtocol::Kerberos(_)
        ));

        match step {
            0 => {
                if self.u2u {
                    assert!(
                        negotiate.first_krb_token().is_none(),
                        "When Kerberos U2U is used, it's impossible to reuse the preflight Kerberos token"
                    );
                } else {
                    assert!(
                        negotiate.first_krb_token().is_some(),
                        "When Kerberos U2U is not used, it's possible to reuse the preflight Kerberos token"
                    );
                }
            }
            1 => {
                assert!(
                    negotiate.first_krb_token().is_none(),
                    "After the second SPNEGO client call, the preflight Kerberos token must be `None`"
                );
            }
            _ => {}
        }
    }
}

/// Validates that the client correctly falls back to NTLM.
pub(super) struct SpnegoKerberosNtlmFallbackValidator;

impl SspiContextValidator for SpnegoKerberosNtlmFallbackValidator {
    fn validate_client(&mut self, step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        assert!(matches!(negotiate.negotiated_protocol(), NegotiatedProtocol::Ntlm(_)));

        if step == 0 {
            assert!(
                negotiate.first_krb_token().is_none(),
                "The Kerberos preflight token must be `None` and SPNEGO must fallback to NTLM"
            );
        }
    }
}

/// Validates that the client correctly falls back to NTLM when the server selected NTLM in SPNEGO instead of Kerberos.
pub(super) struct SpnegoServerNtlmFallbackValidator {
    pub u2u: bool,
}

impl SspiContextValidator for SpnegoServerNtlmFallbackValidator {
    fn validate_client(&mut self, step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        match step {
            0 => {
                if self.u2u {
                    assert!(
                        negotiate.first_krb_token().is_none(),
                        "When Kerberos U2U is used, it's impossible to reuse the preflight Kerberos token"
                    );
                } else {
                    assert!(
                        negotiate.first_krb_token().is_some(),
                        "When Kerberos U2U is not used, it's possible to reuse the preflight Kerberos token"
                    );
                }

                assert!(matches!(
                    negotiate.negotiated_protocol(),
                    NegotiatedProtocol::Kerberos(_)
                ));
            }
            1 => {
                if self.u2u {
                    assert!(negotiate.first_krb_token().is_none());
                } else {
                    // The preflight Kerberos token was not reused because the server fallback to NTLM.
                    assert!(negotiate.first_krb_token().is_some());
                }

                assert!(matches!(negotiate.negotiated_protocol(), NegotiatedProtocol::Ntlm(_)));
            }
            _ => {}
        }
    }
}
