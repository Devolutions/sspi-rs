//! Functions for handling Kerberos messages on both client and server sides.

use std::fmt::Debug;

use oid::ObjectIdentifier;
use picky_asn1::wrapper::{ExplicitContextTag1, ObjectIdentifierAsn1, Optional};
use picky_krb::gss_api::{ApplicationTag0, IAKrbProxyMessage, KrbMessage};
use picky_krb::messages::{IAKerbCookie, IAKerbHeader};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Error, ErrorKind, Result};

/// Decodes incoming [KrbMessage] message and extracts [ApReq] Kerberos message.
pub(super) fn decode_krb_message<T: DeserializeOwned>(data: &[u8], token_id: [u8; 2]) -> Result<T> {
    let krb_message = KrbMessage::<T>::decode_application_krb_message(data)?.0;

    if krb_message.krb5_token_id != token_id {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid kerberos token id: expected {:?} but got {:?}",
                token_id, krb_message.krb5_token_id
            ),
        ));
    }

    Ok(krb_message.krb_msg)
}

pub(super) fn generate_krb_message<T: Serialize + Debug + PartialEq>(
    mech_id: ObjectIdentifier,
    krb5_token_id: [u8; 2],
    krb_msg: T,
) -> Result<Vec<u8>> {
    let krb_blob = ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(mech_id),
        krb5_token_id,
        krb_msg,
    });

    Ok(picky_asn1_der::to_vec(&krb_blob)?)
}

pub(super) fn generate_iakrb_proxy_message<T: Serialize + Debug + PartialEq>(
    cookie: IAKerbCookie,
    krb_msg: T,
) -> Result<Vec<u8>> {
    let iakrb_proxy_blob = ApplicationTag0(IAKrbProxyMessage {
        header: IAKerbHeader {
            // Although the IAKerb RFC specifies that the `target_realm` must be provided,
            // the Windows implementation does not use it.
            // The specification also states that the `target_realm` can be retrieved by sending
            // the `IAKrbProxyMessage` with empty `target_realm` and no Kerberos message. However,
            // the Windows implementation returns an error if the Kerberos message is absent.
            // Therefore, we leave the `target_realm` empty.
            //
            // [IAKERB Realm Retrieval](https://datatracker.ietf.org/doc/html/draft-ietf-kitten-iakerb-03#section-3.1)
            target_realm: ExplicitContextTag1::from(String::new()),
            cookie: Optional(cookie),
            flags: Optional(None),
        },
        krb_msg,
    });

    Ok(picky_asn1_der::to_vec(&iakrb_proxy_blob)?)
}
