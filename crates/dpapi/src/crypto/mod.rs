mod hmac_sha_prf;

use num_bigint_dig::BigUint;
use thiserror::Error;
use rust_kbkdf::{PseudoRandomFunction, PseudoRandomFunctionKey};
use uuid::Uuid;

use self::hmac_sha_prf::*;
use crate::gkdi::{EcdhKey, EllipticCurve, FfcdhKey, GroupKeyEnvelope, HashAlg};
use crate::rpc::{Decode, Encode};
use crate::utils::encode_utf16_le;
use crate::DpapiResult;

#[derive(Debug, Error)]
pub enum CryptoError {
}

// "KDS service\0" encoded in UTF16 le.
const KDS_SERVICE_LABEL: &[u8] = &[
    75, 0, 68, 0, 83, 0, 32, 0, 115, 0, 101, 0, 114, 0, 118, 0, 105, 0, 99, 0, 101, 0, 0, 0,
];

fn kdf(algorithm: HashAlg, secret: &[u8], label: &[u8], context: &[u8], length: usize) -> DpapiResult<Vec<u8>> {
    use rust_kbkdf::{kbkdf, CounterLocation, CounterMode, InputType, KDFMode, SpecifiedInput};

    let mut derived_key = vec![0; length];

    macro_rules! kdf {
        ($sha:ident) => {{
            let key = HmacShaPrfKey::new(secret);
            let mut hmac = $sha::new();

            // KDF(HashAlg, KI, Label, Context, L)
            // where KDF is SP800-108 in counter mode.
            kbkdf(
                &KDFMode::CounterMode(CounterMode { counter_length: 32 }),
                &InputType::SpecifiedInput(SpecifiedInput { label, context }),
                &key,
                &mut hmac,
                &mut derived_key,
            )?;
        }};
    }

    match algorithm {
        HashAlg::Sha1 => kdf!(HmacSha1Prf),
        HashAlg::Sha256 => kdf!(HmacSha256Prf),
        HashAlg::Sha384 => kdf!(HmacSha384Prf),
        HashAlg::Sha512 => kdf!(HmacSha512Prf),
    }

    Ok(derived_key)
}

fn kdf_concat(
    algorithm: HashAlg,
    shared_secret: &[u8],
    algorithm_id: &[u8],
    party_uinfo: &[u8],
    party_vinfo: &[u8],
) -> DpapiResult<Vec<u8>> {
    let mut other_info = algorithm_id.to_vec();
    other_info.extend_from_slice(party_uinfo);
    other_info.extend_from_slice(party_vinfo);

    Ok(match algorithm {
        HashAlg::Sha1 => concat_kdf::derive_key::<sha1::Sha1>(shared_secret, &other_info, 20)?,
        HashAlg::Sha256 => concat_kdf::derive_key::<sha2::Sha256>(shared_secret, &other_info, 32)?,
        HashAlg::Sha384 => concat_kdf::derive_key::<sha2::Sha384>(shared_secret, &other_info, 48)?,
        HashAlg::Sha512 => concat_kdf::derive_key::<sha2::Sha512>(shared_secret, &other_info, 64)?,
    })
}

fn compute_kdf_context(key_guid: Uuid, l0: i32, l1: i32, l2: i32) -> Vec<u8> {
    let mut buf = vec![0; 28];

    buf[0..16].copy_from_slice(&key_guid.to_bytes_le());
    buf[16..20].copy_from_slice(&l0.to_le_bytes());
    buf[20..24].copy_from_slice(&l1.to_le_bytes());
    buf[24..28].copy_from_slice(&l2.to_le_bytes());

    buf
}

pub fn compute_l1_key(
    target_sd: &[u8],
    root_key_id: Uuid,
    l0: i32,
    root_key: &[u8],
    algorithm: HashAlg,
) -> DpapiResult<Vec<u8>> {
    // Note: 512 is number of bits, we use byte length here
    // Key(SD, RK, L0, -1, -1) = KDF(
    //   HashAlg,
    //   RK.msKds-RootKeyData,
    //   "KDS service",
    //   RKID || L0 || 0xffffffff || 0xffffffff,
    //   512
    // )
    let l0_seed = kdf(
        algorithm,
        root_key,
        KDS_SERVICE_LABEL,
        &compute_kdf_context(root_key_id, l0, -1, -1),
        64,
    )?;

    // Key(SD, RK, L0, 31, -1) = KDF(
    //   HashAlg,
    //   Key(SD, RK, L0, -1, -1),
    //   "KDS service",
    //   RKID || L0 || 31 || 0xffffffff || SD,
    //   512
    // )
    let mut kdf_context = compute_kdf_context(root_key_id, l0, 31, -1);
    kdf_context.extend_from_slice(target_sd);

    kdf(algorithm, &l0_seed, KDS_SERVICE_LABEL, &kdf_context, 64)
}

pub fn compute_l2_key(
    algorithm: HashAlg,
    request_l1: i32,
    request_l2: i32,
    rk: &GroupKeyEnvelope,
) -> DpapiResult<Vec<u8>> {
    let mut l1 = rk.l1;
    let mut l1_key = rk.l1_key.clone();
    let mut l2 = rk.l2;
    let mut l2_key = rk.l2_key.clone();
    let mut reseed_l2 = l2 == 31 || rk.l1 != request_l1;

    //  MS-GKDI 2.2.4 Group key Envelope
    //  If the value in the L2 index field is equal to 31, this contains the
    //  L1 key with group key identifier (L0 index, L1 index, -1). In all
    //  other cases, this field contains the L1 key with group key identifier
    //  (L0 index, L1 index - 1, -1). If this field is present, its length
    //  MUST be equal to 64 bytes.
    if l2 != 31 && l1 != request_l1 {
        l1 -= 1;
    }

    while l1 != request_l1 {
        reseed_l2 = true;
        l1 -= 1;

        l1_key = kdf(
            algorithm,
            &l1_key,
            KDS_SERVICE_LABEL,
            &compute_kdf_context(rk.root_key_identifier, rk.l0, l1, -1),
            64,
        )?;
    }

    if reseed_l2 {
        l2 = 31;
        l2_key = kdf(
            algorithm,
            &l1_key,
            KDS_SERVICE_LABEL,
            &compute_kdf_context(rk.root_key_identifier, rk.l0, l1, l2),
            64,
        )?;
    }

    while l2 != request_l2 {
        l2 -= 1;

        l2_key = kdf(
            algorithm,
            &l2_key,
            KDS_SERVICE_LABEL,
            &compute_kdf_context(rk.root_key_identifier, rk.l0, l1, l2),
            64,
        )?;
    }

    Ok(l2_key)
}

pub fn compute_kek_from_public_key(
    algorithm: HashAlg,
    seed: &[u8],
    secret_algorithm: &str,
    secret_parameters: Option<&[u8]>,
    public_key: &[u8],
    private_key_length: usize,
) -> DpapiResult<Vec<u8>> {
    let encoded_secret_algorithm = encode_utf16_le(secret_algorithm);

    let private_key = kdf(
        algorithm,
        seed,
        KDS_SERVICE_LABEL,
        &encoded_secret_algorithm,
        private_key_length,
    )?;

    compute_kek(algorithm, secret_algorithm, secret_parameters, &private_key, public_key)
}

fn compute_kek(
    algorithm: HashAlg,
    secret_algorithm: &str,
    secret_parameters: Option<&[u8]>,
    private_key: &[u8],
    public_key: &[u8],
) -> DpapiResult<Vec<u8>> {
    let (shared_secret, secret_hash_algorithm) = if secret_algorithm == "DH" {
        let dh_pub_key = FfcdhKey::decode(public_key)?;
        let shared_secret = dh_pub_key
            .public_key
            .modpow(&BigUint::from_bytes_be(private_key), &dh_pub_key.field_order);
        let mut shared_secret = shared_secret.to_bytes_be();

        while shared_secret.len() < dh_pub_key.key_length.try_into()? {
            shared_secret.insert(0, 0);
        }

        (shared_secret, HashAlg::Sha256)
    } else if secret_algorithm.starts_with("ECDH_P") {
        use elliptic_curve::scalar::ScalarPrimitive;
        use elliptic_curve::sec1::FromEncodedPoint;
        use elliptic_curve::{PublicKey, SecretKey};

        let ecdh_pub_key_info = EcdhKey::decode(public_key)?;

        match ecdh_pub_key_info.curve {
            EllipticCurve::P256 => {
                let public_key: p256::PublicKey = Option::from(PublicKey::from_encoded_point(
                    &p256::EncodedPoint::from_affine_coordinates(
                        ecdh_pub_key_info.x.to_bytes_be().as_slice().into(),
                        ecdh_pub_key_info.y.to_bytes_be().as_slice().into(),
                        false,
                    ),
                ))
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NteInternalError,
                        "invalid ECDH public key: bad point coordinates",
                    )
                })?;
                let secret_key = SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let shared_secret: p256::ecdh::SharedSecret =
                    p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

                (shared_secret.raw_secret_bytes().as_slice().to_vec(), HashAlg::Sha256)
            }
            EllipticCurve::P384 => {
                let public_key: p384::PublicKey = Option::from(PublicKey::from_encoded_point(
                    &p384::EncodedPoint::from_affine_coordinates(
                        ecdh_pub_key_info.x.to_bytes_be().as_slice().into(),
                        ecdh_pub_key_info.y.to_bytes_be().as_slice().into(),
                        false,
                    ),
                ))
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NteInternalError,
                        "invalid ECDH public key: bad point coordinates",
                    )
                })?;
                let secret_key = SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let shared_secret: p384::ecdh::SharedSecret =
                    p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

                (shared_secret.raw_secret_bytes().as_slice().to_vec(), HashAlg::Sha384)
            }
            EllipticCurve::P521 => {
                let public_key: p521::PublicKey = Option::from(PublicKey::from_encoded_point(
                    &p521::EncodedPoint::from_affine_coordinates(
                        ecdh_pub_key_info.x.to_bytes_be().as_slice().into(),
                        ecdh_pub_key_info.y.to_bytes_be().as_slice().into(),
                        false,
                    ),
                ))
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NteInternalError,
                        "invalid ECDH public key: bad point coordinates",
                    )
                })?;
                let secret_key = SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let shared_secret: p521::ecdh::SharedSecret =
                    p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

                (shared_secret.raw_secret_bytes().as_slice().to_vec(), HashAlg::Sha512)
            }
        }
    } else {
        return Err(Error::new(
            ErrorKind::NteInternalError,
            format!("unsupported or invalid secret algorithm: {}", secret_algorithm),
        ));
    };

    // "KDS public key\0" encoded in UTF16 le.
    let kek_context = &[
        75, 0, 68, 0, 83, 0, 32, 0, 112, 0, 117, 0, 98, 0, 108, 0, 105, 0, 99, 0, 32, 0, 107, 0, 101, 0, 121, 0, 0, 0,
    ];

    // This part isn't documented but we use the key derivation algorithm
    // SP 800-56A to derive the kek secret input value. On Windows this uses
    // BCryptDeriveKey with the following parameters.
    //   KDF_ALGORITHMID - SHA512
    //   KDF_PARTYUINFO  - KDS public key
    //   KDF_PARTYVINFO  - KDS service
    // Each of these is just appended to the otherinfo value used in
    // cryptography as the UTF-16-LE NULL terminated strings.
    let secret = kdf_concat(
        secret_hash_algorithm,
        &shared_secret,
        // "SHA512\0" encoded in UTF16 le.
        &[83, 0, 72, 0, 65, 0, 53, 0, 49, 0, 50, 0, 0, 0],
        kek_context,
        KDS_SERVICE_LABEL,
    )?;

    kdf(algorithm, &secret, KDS_SERVICE_LABEL, kek_context, 32)
}

fn compute_public_key(
    secret_algorithm: &str,
    secret_parameters: Option<&[u8]>,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> DpapiResult<Vec<u8>> {
    if secret_algorithm == "DH" {
        let FfcdhKey {
            key_length,
            field_order,
            generator,
            public_key,
        } = FfcdhKey::decode(peer_public_key)?;

        let my_pub_key = generator.modpow(&BigUint::from_bytes_be(private_key), &field_order);

        FfcdhKey {
            key_length,
            field_order,
            generator,
            public_key: my_pub_key,
        }
        .encode_to_vec()
    } else if secret_algorithm.starts_with("ECDH_P") {
        use elliptic_curve::scalar::ScalarPrimitive;
        use elliptic_curve::sec1::{EncodedPoint, ToEncodedPoint};
        use elliptic_curve::{PublicKey, SecretKey};

        let ecdh_pub_key_info = EcdhKey::decode(peer_public_key)?;

        let (x, y) = match ecdh_pub_key_info.curve {
            EllipticCurve::P256 => {
                let secret_key = p256::SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let public_key = secret_key.public_key();
                let point = public_key.to_encoded_point(false);

                (
                    BigUint::from_bytes_be(
                        &point
                            .x()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point x coordinate"))?
                            .to_vec(),
                    ),
                    BigUint::from_bytes_be(
                        &point
                            .y()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point y coordinate"))?
                            .to_vec(),
                    ),
                )
            }
            EllipticCurve::P384 => {
                let secret_key = p384::SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let public_key = secret_key.public_key();
                let point = public_key.to_encoded_point(false);

                (
                    BigUint::from_bytes_be(
                        &point
                            .x()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point x coordinate"))?
                            .to_vec(),
                    ),
                    BigUint::from_bytes_be(
                        &point
                            .y()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point y coordinate"))?
                            .to_vec(),
                    ),
                )
            }
            EllipticCurve::P521 => {
                let secret_key = p521::SecretKey::new(ScalarPrimitive::from_slice(private_key)?);
                let public_key = secret_key.public_key();
                let point = public_key.to_encoded_point(false);

                (
                    BigUint::from_bytes_be(
                        &point
                            .x()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point x coordinate"))?
                            .to_vec(),
                    ),
                    BigUint::from_bytes_be(
                        &point
                            .y()
                            .ok_or_else(|| Error::new(ErrorKind::NteInternalError, "missing curve point y coordinate"))?
                            .to_vec(),
                    ),
                )
            }
        };

        EcdhKey {
            curve: ecdh_pub_key_info.curve,
            key_length: ecdh_pub_key_info.key_length,
            x,
            y,
        }
        .encode_to_vec()
    } else {
        Err(Error::new(
            ErrorKind::NteInternalError,
            format!("unsupported or invalid secret algorithm: {}", secret_algorithm),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_KEY: &[u8] = &[
        213, 85, 238, 100, 120, 222, 109, 53, 48, 101, 43, 187, 152, 206, 110, 105, 123, 251, 227, 253, 232, 85, 197,
        24, 217, 190, 118, 74, 54, 226, 8, 188, 163, 141, 155, 170, 208, 164, 97, 125, 32, 172, 65, 183, 251, 135, 229,
        224, 214, 22, 98, 18, 170, 254, 220, 105, 217, 11, 142, 135, 141, 104, 82, 189,
    ];
    const CONTEXT: &[u8] = &[
        228, 137, 183, 195, 107, 83, 44, 167, 62, 235, 215, 116, 108, 38, 108, 149, 107, 206, 154, 191, 189, 219, 105,
        175, 72, 213, 172, 131, 94, 207, 58, 208,
    ];

    #[test]
    fn test_kdf_sha1() {
        let expected_key = [
            117, 25, 15, 198, 42, 170, 180, 156, 140, 156, 188, 164, 163, 245, 40, 18, 53, 43, 149, 141, 135, 152, 11,
            248, 80, 84, 1, 195, 212, 7, 149, 35,
        ];

        let key = kdf(HashAlg::Sha1, SECRET_KEY, KDS_SERVICE_LABEL, CONTEXT, 32).unwrap();

        assert_eq!(expected_key[..], key[..]);
    }

    #[test]
    fn test_kdf_sha256() {
        let expected_key = [
            95, 246, 71, 210, 202, 186, 163, 251, 24, 175, 54, 107, 191, 107, 87, 35, 241, 202, 64, 106, 34, 201, 185,
            5, 213, 175, 222, 111, 249, 145, 238, 162,
        ];

        let key = kdf(HashAlg::Sha256, SECRET_KEY, KDS_SERVICE_LABEL, CONTEXT, 32).unwrap();

        assert_eq!(expected_key[..], key[..]);
    }

    #[test]
    fn test_kdf_sha384() {
        let expected_key = [
            91, 218, 125, 86, 51, 207, 96, 224, 6, 253, 16, 137, 142, 10, 95, 156, 163, 217, 31, 186, 206, 88, 81, 141,
            231, 62, 224, 200, 168, 156, 189, 71, 60, 220, 166, 65, 141, 47, 92, 145, 241, 112, 91, 39, 27, 237, 88,
            122, 103, 38, 115, 222, 26, 214, 185, 78, 34, 7, 170, 54, 74, 18, 206, 75,
        ];

        let key = kdf(HashAlg::Sha384, SECRET_KEY, KDS_SERVICE_LABEL, CONTEXT, 64).unwrap();

        assert_eq!(expected_key[..], key[..]);
    }

    #[test]
    fn test_kdf_sha512() {
        let expected_key = [
            56, 219, 230, 175, 76, 173, 241, 49, 216, 97, 145, 27, 74, 153, 173, 79, 201, 145, 64, 135, 166, 0, 111,
            19, 164, 112, 171, 230, 130, 28, 71, 240, 122, 88, 46, 26, 192, 243, 50, 182, 242, 217, 179, 190, 12, 13,
            85, 1, 202, 211, 212, 169, 83, 208, 162, 227, 217, 30, 33, 226, 101, 230, 8, 109,
        ];

        let key = kdf(HashAlg::Sha512, SECRET_KEY, KDS_SERVICE_LABEL, CONTEXT, 64).unwrap();

        assert_eq!(expected_key[..], key[..]);
    }
}
