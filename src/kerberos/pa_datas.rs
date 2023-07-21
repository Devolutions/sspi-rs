use picky_asn1_x509::signed_data::SignedData;
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::diffie_hellman::{generate_key, DhNonce};
use picky_krb::data_types::PaData;
use picky_krb::messages::AsRep;
use picky_krb::pkinit::PaPkAsRep;

use super::client::extractors::extract_session_key_from_as_rep;
use super::{
    GenerateAsPaDataOptions as PasswordBasedPaDataOptions,
    generate_pa_datas_for_as_req as generate_password_based, EncryptionParams,
};
use crate::pk_init::{
    GenerateAsPaDataOptions as PrivateKeyBasedPaDataOptions,
    generate_pa_datas_for_as_req as generate_private_key_based, DhParameters, extract_server_dh_public_key,
};
use crate::{Result, Error, ErrorKind, check_if_empty};
use crate::pku2u::{extract_pa_pk_as_rep, validate_signed_data, validate_server_p2p_certificate, extract_server_nonce};

pub enum AsReqPaDataOptions<'a> {
    PasswordBased(PasswordBasedPaDataOptions<'a>),
    PrivateKeyBased(PrivateKeyBasedPaDataOptions<'a>),
}

impl AsReqPaDataOptions<'_> {
    pub fn generate(&self) -> Result<Vec<PaData>> {
        match self {
            AsReqPaDataOptions::PasswordBased(options) => generate_password_based(options),
            AsReqPaDataOptions::PrivateKeyBased(options) => generate_private_key_based(options),
        }
    }

    pub fn with_pre_auth(&mut self, pre_auth: bool) {
        match self {
            AsReqPaDataOptions::PasswordBased(options) => options.with_pre_auth = pre_auth,
            AsReqPaDataOptions::PrivateKeyBased(_) => {},
        }
    }

    pub fn with_salt(&mut self, salt: Vec<u8>) {
        match self {
            AsReqPaDataOptions::PasswordBased(options) => options.salt = salt,
            AsReqPaDataOptions::PrivateKeyBased(_) => {},
        }
    }
}

pub enum AsRepSessionKeyExtractor<'a> {
    PasswordBased {
        salt: &'a str,
        password: &'a str,
        enc_params: &'a EncryptionParams,
    },
    PrivateKeyBased {
        dh_parameters: &'a mut DhParameters,
        enc_params: &'a mut EncryptionParams,
    },
}

impl AsRepSessionKeyExtractor<'_> {
    pub fn session_key(&mut self, as_rep: &AsRep) -> Result<Vec<u8>> {
        match self {
            AsRepSessionKeyExtractor::PasswordBased {
                salt,
                password,
                enc_params,
            } => extract_session_key_from_as_rep(as_rep, salt, password, enc_params),
            AsRepSessionKeyExtractor::PrivateKeyBased { dh_parameters, enc_params } => {
                let dh_rep_info = match extract_pa_pk_as_rep(&as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP",
                        ))
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;
                dh_parameters.server_nonce = Some(server_nonce);

                let signed_data: SignedData = picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;

                let rsa_public_key = validate_server_p2p_certificate(&signed_data)?;
                validate_signed_data(&signed_data, &rsa_public_key)?;

                let public_key = extract_server_dh_public_key(&signed_data)?;
                dh_parameters.other_public_key = Some(public_key);

                enc_params.encryption_type =
                    Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0 .0.as_slice())?);

                Ok(generate_key(
                    check_if_empty!(dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                    &dh_parameters.private_key,
                    &dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: check_if_empty!(
                            dh_parameters.client_nonce.as_ref(),
                            "dh client none is not set"
                        ),
                        server_nonce: check_if_empty!(
                            dh_parameters.server_nonce.as_ref(),
                            "dh server nonce is not set"
                        ),
                    }),
                    check_if_empty!(
                        enc_params.encryption_type.as_ref(),
                        "encryption type is not set"
                    )
                    .cipher()
                    .as_ref(),
                )?)
            },
        }
    }
}
