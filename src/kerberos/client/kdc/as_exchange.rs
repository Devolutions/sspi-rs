use picky_krb::data_types::KrbResult;
use picky_krb::messages::{AsRep, AsReq, IAKerbCookie, KdcReqBody};

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_salt_from_krb_error;
use crate::kerberos::client::generators::{GenerateAsPaDataOptions, GenerateKeytabPaDataOptions, generate_as_req};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::pa_datas::AsReqPaDataOptions;
#[cfg(feature = "scard")]
use crate::pk_init::DhParameters;
use crate::{CredentialsBuffers, Error, ErrorKind, Result, Secret};

pub(crate) enum AsExchangeOutput {
    SendRequest(AsReq),
    Done(AsRep),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AsExchangeState {
    Initial,
    ErrorResponse,
    AsRepResponse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsExchange {
    state: AsExchangeState,
    iakerb: bool,
    kdc_req_body: KdcReqBody,
    // Instead of storing the `AsReqPaDataOptions` directly, we store its individual components (fields below).
    // This design avoids introducing lifetime requirement that would require huge refactoring.
    // The `AsReqPaDataOptions` is cheaply reconstructed at each step using the `build_pa_data_options` method.
    password: Secret<String>,
    salt: Vec<u8>,
    #[cfg(feature = "scard")]
    dh_parameters: DhParameters,
    #[cfg(feature = "scard")]
    authenticator_nonce: [u8; 4],
}

impl AsExchange {
    pub(crate) fn new(
        iakerb: bool,
        kdc_req_body: KdcReqBody,
        password: Secret<String>,
        salt: Vec<u8>,
        #[cfg(feature = "scard")] dh_parameters: DhParameters,
        #[cfg(feature = "scard")] authenticator_nonce: [u8; 4],
    ) -> Self {
        Self {
            state: AsExchangeState::Initial,
            iakerb,
            kdc_req_body,
            password,
            salt,
            #[cfg(feature = "scard")]
            dh_parameters,
            #[cfg(feature = "scard")]
            authenticator_nonce,
        }
    }

    pub(crate) fn step(
        &mut self,
        credentials: &CredentialsBuffers,
        enc_params: &EncryptionParams,
        response: &[u8],
        iakerb_cookie: &mut IAKerbCookie,
        iakerb_gss_transcript: &mut Vec<u8>,
    ) -> Result<AsExchangeOutput> {
        match self.state {
            AsExchangeState::Initial => {
                let mut pa_data_options = self.build_pa_data_options(credentials, enc_params)?;

                pa_data_options.with_pre_auth(false);
                let pa_datas = pa_data_options.generate()?;
                let as_req = generate_as_req(pa_datas, self.kdc_req_body.clone());

                self.state = AsExchangeState::ErrorResponse;
                Ok(AsExchangeOutput::SendRequest(as_req))
            }
            AsExchangeState::ErrorResponse => {
                let as_rep: KrbResult<AsRep> =
                    decode_kdc_reply(response, self.iakerb, iakerb_cookie, iakerb_gss_transcript)?;

                if as_rep.is_ok() {
                    error!(
                        "KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected."
                    );

                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "KDC server should not process AS_REQ without the pa-pac data",
                    ));
                }

                let mut pa_data_options = self.build_pa_data_options(credentials, enc_params)?;

                if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
                    debug!("salt extracted successfully from the KRB_ERROR");

                    pa_data_options.with_salt(correct_salt.into_bytes());
                }

                pa_data_options.with_pre_auth(true);
                let pa_datas = pa_data_options.generate()?;

                self.state = AsExchangeState::AsRepResponse;
                Ok(AsExchangeOutput::SendRequest(generate_as_req(
                    pa_datas,
                    self.kdc_req_body.clone(),
                )))
            }
            AsExchangeState::AsRepResponse => {
                let as_rep: KrbResult<AsRep> =
                    decode_kdc_reply(response, self.iakerb, iakerb_cookie, iakerb_gss_transcript)?;
                Ok(AsExchangeOutput::Done(
                    as_rep.inspect_err(|err| error!(?err, "AS exchange error"))?,
                ))
            }
        }
    }

    fn build_pa_data_options<'a>(
        &'a mut self,
        credentials: &'a CredentialsBuffers,
        enc_params: &EncryptionParams,
    ) -> Result<AsReqPaDataOptions<'a>> {
        Ok(match credentials {
            CredentialsBuffers::AuthIdentity(_) => AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password: self.password.as_ref(),
                salt: self.salt.clone(),
                enc_params: enc_params.clone(),
                with_pre_auth: false,
            }),
            CredentialsBuffers::Keytab(keytab) => AsReqPaDataOptions::Keytab(GenerateKeytabPaDataOptions {
                key: keytab.key.clone(),
                key_enctype: keytab.key_enctype.clone(),
                with_pre_auth: false,
            }),
            #[cfg(feature = "scard")]
            CredentialsBuffers::SmartCard(scard_identity_buffer) => {
                use sha1::{Digest, Sha1};

                use crate::smartcard::SmartCard;
                use crate::{SmartCardIdentity, pk_init};

                let scard_identity = SmartCardIdentity::try_from(scard_identity_buffer)?;

                let mut smart_card = SmartCard::from_credentials(&scard_identity)?;
                let p2p_cert = scard_identity.certificate;

                AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                    p2p_cert,
                    kdc_req_body: &self.kdc_req_body,
                    dh_parameters: self.dh_parameters.clone(),
                    sign_data: Box::new(move |data_to_sign| {
                        let mut sha1 = Sha1::new();
                        sha1.update(data_to_sign);
                        let digest = sha1.finalize().to_vec();

                        smart_card.sign(digest)
                    }),
                    with_pre_auth: false,
                    authenticator_nonce: self.authenticator_nonce,
                }))
            }
        })
    }
}
