//! The acceptor may protect the per-message tokens with a subkey whose type differs from the type of the ticket
//! session key ([RFC 4121, section 2](https://www.rfc-editor.org/rfc/rfc4121#section-2)).

use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::AP_REP_TOKEN_ID;
use picky_krb::constants::key_usages::{AP_REP_ENC, INITIATOR_SIGN};
use picky_krb::constants::types::AP_REP_MSG_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::data_types::{
    EncApRepPart, EncApRepPartInner, EncryptedData, EncryptionKey, KerberosTime, Microseconds,
};
use picky_krb::gss_api::MicToken;
use picky_krb::messages::{ApRep, ApRepInner};
use time::OffsetDateTime;

use super::{KerberosClientState, generate_krb_message};
use crate::kerberos::test_data::fake_client;
use crate::{
    BufferType, ClientRequestFlags, CredentialsBuffers, DataRepresentation, Kerberos, KerberosState, SecurityBuffer,
    SecurityStatus, Sspi, SspiEx, SspiImpl,
};

/// An AES128 key: 16 octets, the key size of `aes128-cts-hmac-sha1-96` in RFC 3962 §6.
const AES128_SUBKEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// Builds the AP-REP the way an acceptor does, but with a subkey of another type than the ticket session key:
/// an `AES256` session key and an `AES128` subkey.
fn ap_rep_with_aes128_subkey(client: &Kerberos) -> ApRep {
    let session_key = client.encryption_params.session_key.as_ref().expect("fake session key");
    let aes256 = CipherSuite::Aes256CtsHmacSha196;
    let aes128 = CipherSuite::Aes128CtsHmacSha196;

    let enc_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(OffsetDateTime::now_utc()))),
        cusec: ExplicitContextTag1::from(Microseconds::from(vec![0])),
        subkey: Optional::from(Some(ExplicitContextTag2::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&aes128)])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(AES128_SUBKEY.to_vec())),
        }))),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![0x2a])))),
    });
    let cipher = aes256
        .cipher()
        .encrypt(
            session_key.as_ref(),
            AP_REP_ENC,
            &picky_asn1_der::to_vec(&enc_part).unwrap(),
        )
        .unwrap();

    ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REP_MSG_TYPE])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&aes256)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
        }),
    })
}

/// Feeds the AP-REP to a client that waits for it.
fn finish_ap_exchange(dce_style: bool) -> Kerberos {
    let mut client = fake_client();
    client.state = KerberosState::Client(Box::new(KerberosClientState::ApExchange));

    let ap_rep = ap_rep_with_aes128_subkey(&client);
    let (token, flags) = if dce_style {
        (
            picky_asn1_der::to_vec(&ap_rep).unwrap(),
            ClientRequestFlags::USE_DCE_STYLE | ClientRequestFlags::MUTUAL_AUTH,
        )
    } else {
        (
            generate_krb_message(oids::krb5(), AP_REP_TOKEN_ID, ap_rep).unwrap(),
            ClientRequestFlags::MUTUAL_AUTH,
        )
    };

    let mut credentials: Option<CredentialsBuffers> = None;
    let mut input = [SecurityBuffer::new(token, BufferType::Token)];
    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut builder = client
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input)
        .with_output(&mut output);
    let status = SspiImpl::initialize_security_context_impl(&mut client, &mut builder)
        .unwrap()
        .resolve_to_result()
        .unwrap()
        .status;
    assert_eq!(status, SecurityStatus::Ok);

    client
}

/// The MIC token of the client is the observable: its checksum is keyed by the subkey and sized by its type.
fn assert_mic_follows_the_subkey_type(client: &mut Kerberos) {
    let data = b"SPNEGO mechTypes";
    let token = client.generate_mic_token(data, crate::private::Sealed).unwrap();
    let mic_token = MicToken::decode(token.as_slice()).unwrap();

    let mut checksum_input = data.to_vec();
    checksum_input.extend_from_slice(&mic_token.header());
    let expected = checksum_sha_aes(&AES128_SUBKEY, INITIATOR_SIGN, &checksum_input, &AesSize::Aes128).unwrap();

    assert_eq!(mic_token.checksum, expected);
}

#[test]
fn the_client_switches_to_the_subkey_type_of_the_ap_rep() {
    let mut client = finish_ap_exchange(false);

    assert_eq!(
        client.encryption_params.encryption_type,
        Some(CipherSuite::Aes128CtsHmacSha196)
    );
    assert_mic_follows_the_subkey_type(&mut client);
}

#[test]
fn the_dce_client_switches_to_the_subkey_type_of_the_ap_rep() {
    let mut client = finish_ap_exchange(true);

    assert_eq!(
        client.encryption_params.encryption_type,
        Some(CipherSuite::Aes128CtsHmacSha196)
    );
    assert_mic_follows_the_subkey_type(&mut client);
}
