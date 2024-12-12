mod hmac_sha_prf;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_kw::KekAes256;
use num_bigint_dig::BigUint;
use thiserror::Error;
use rust_kbkdf::{PseudoRandomFunction, PseudoRandomFunctionKey};
use picky_asn1_x509::enveloped_data::{ContentEncryptionAlgorithmIdentifier, KeyEncryptionAlgorithmIdentifier};
use picky_asn1_x509::{oids, AesParameters, AlgorithmIdentifierParameters};
use rand::Rng;
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

pub fn cek_decrypt(
    algorithm: &KeyEncryptionAlgorithmIdentifier,
    kek: &[u8],
    wrapped_key: &[u8],
) -> DpapiResult<Vec<u8>> {
    if algorithm.oid() != &oids::aes256_wrap() {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "unexpected algorithm oid: expected aes256-wrap",
        ));
    }

    let kek = KekAes256::new(kek.into());

    Ok(kek.unwrap_vec(wrapped_key)?)
}

pub fn cek_encrypt(algorithm: &KeyEncryptionAlgorithmIdentifier, kek: &[u8], key: &[u8]) -> DpapiResult<Vec<u8>> {
    if algorithm.oid() != &oids::aes256_wrap() {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "unexpected algorithm oid: expected aes256-wrap",
        ));
    }

    let kek = KekAes256::new(kek.into());

    Ok(kek.wrap_vec(key)?)
}

pub fn cek_generate(algorithm: &KeyEncryptionAlgorithmIdentifier) -> DpapiResult<(Vec<u8>, Vec<u8>)> {
    if algorithm.oid() != &oids::aes256_wrap() {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "unexpected algorithm oid: expected aes256-wrap",
        ));
    }

    let mut rng = OsRng;
    let cek = Aes256Gcm::generate_key(&mut rng);
    let iv = rng.gen::<[u8; 12]>();

    Ok((cek.to_vec(), iv.to_vec()))
}

pub fn content_decrypt(
    algorithm: &ContentEncryptionAlgorithmIdentifier,
    cek: &[u8],
    data: &[u8],
) -> DpapiResult<Vec<u8>> {
    if algorithm.oid() != &oids::aes256_gcm() {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "unexpected algorithm oid: expected aes256-gcm",
        ));
    }

    let iv = if let AlgorithmIdentifierParameters::Aes(aes_parameters) = algorithm.parameters() {
        if let AesParameters::InitializationVector(iv) = aes_parameters {
            iv.0.as_slice()
        } else {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid aes parameters: expected initialization vector",
            ));
        }
    } else {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "invalid aes parameters: missing",
        ));
    };

    let mut cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(cek));
    Ok(cipher.decrypt(iv.into(), data)?)
}

pub fn content_encrypt(
    algorithm: &ContentEncryptionAlgorithmIdentifier,
    cek: &[u8],
    plaintext: &[u8],
) -> DpapiResult<Vec<u8>> {
    if algorithm.oid() != &oids::aes256_gcm() {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "unexpected algorithm oid: expected aes256-gcm",
        ));
    }

    let iv = if let AlgorithmIdentifierParameters::Aes(aes_parameters) = algorithm.parameters() {
        if let AesParameters::InitializationVector(iv) = aes_parameters {
            iv.0.as_slice()
        } else {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid aes parameters: expected initialization vector",
            ));
        }
    } else {
        return Err(Error::new(
            ErrorKind::NteInvalidParameter,
            "invalid aes parameters: missing",
        ));
    };

    let mut cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(cek));
    Ok(cipher.encrypt(iv.into(), plaintext)?)
}

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
    use picky_asn1::wrapper::OctetStringAsn1;
    use picky_asn1_x509::AesMode;

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
    const SECRET_PARAMETERS_DH: &[u8] = &[
        12, 2, 0, 0, 68, 72, 80, 77, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89,
        153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212,
        250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124,
        32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192,
        34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155,
        184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166,
        183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82,
        77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180,
        134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11,
        230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152,
        175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21,
        151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84,
        7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190,
        58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165,
        90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125,
        230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29,
        20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164,
        189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200,
        72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53,
        59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75,
        82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39,
        207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89,
    ];
    const PRIVATE_KEY_DH: &[u8] = &[
        139, 93, 50, 184, 90, 214, 77, 2, 57, 23, 5, 0, 155, 2, 202, 140, 58, 27, 111, 51, 97, 204, 165, 167, 18, 41,
        158, 25, 48, 44, 42, 198, 74, 238, 245, 201, 107, 49, 243, 27, 164, 205, 223, 112, 31, 100, 146, 48, 90, 81,
        126, 112, 38, 0, 194, 4, 195, 140, 122, 134, 104, 123, 211, 100,
    ];
    const PUBLIC_KEY_DH: &[u8] = &[
        68, 72, 80, 66, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140,
        238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247,
        223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12,
        100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224,
        177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188,
        57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45,
        82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246,
        161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179,
        202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195,
        163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22,
        210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44,
        155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58,
        26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12,
        107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65,
        0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170,
        184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143,
        111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255,
        232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30,
        5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100,
        224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178,
        70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197,
        130, 102, 75, 76, 15, 108, 196, 22, 89, 63, 246, 158, 197, 238, 228, 177, 87, 255, 7, 170, 179, 251, 65, 155,
        170, 131, 138, 187, 46, 97, 142, 5, 165, 60, 250, 49, 231, 45, 194, 253, 138, 19, 51, 17, 14, 58, 138, 220,
        159, 243, 234, 232, 20, 213, 21, 252, 63, 24, 156, 7, 240, 21, 148, 36, 254, 147, 3, 29, 43, 52, 13, 13, 153,
        78, 16, 128, 153, 153, 114, 253, 211, 219, 59, 84, 206, 244, 233, 243, 222, 144, 228, 133, 135, 176, 87, 48,
        253, 16, 188, 170, 171, 53, 228, 102, 234, 1, 38, 120, 251, 65, 104, 155, 189, 160, 74, 150, 128, 13, 242, 122,
        148, 52, 206, 158, 237, 95, 106, 96, 236, 190, 43, 173, 141, 144, 42, 198, 40, 92, 242, 100, 42, 54, 249, 250,
        249, 97, 19, 168, 10, 109, 182, 35, 138, 248, 158, 153, 45, 181, 175, 160, 65, 6, 210, 191, 73, 164, 230, 167,
        12, 140, 148, 222, 156, 10, 62, 149, 64, 13, 150, 200, 169, 109, 49, 149, 52, 227, 37, 250, 250, 208, 109, 50,
        187, 91, 242, 40, 102, 200, 248, 182, 96, 18, 87, 71, 238, 88, 8, 220, 157, 201, 237, 178, 250, 211, 77, 95,
        21, 98, 248, 205, 24, 172, 212, 96, 169, 101, 35, 47, 40, 187, 132, 216, 243, 39, 131, 24, 135, 88, 17, 245,
        208, 83, 162, 58, 194, 84, 192, 227, 105, 145, 134, 13, 44, 216, 9, 102, 61, 99, 224, 239, 153, 66, 232, 191,
        24,
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

    #[test]
    fn test_compute_public_key_dh() {
        let expected_key = [
            68, 72, 80, 66, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153,
            140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212,
            250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154,
            124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71,
            88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177,
            229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225,
            202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52,
            119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202,
            203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222,
            212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164,
            181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202,
            219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72,
            76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63,
            255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111,
            98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87,
            242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130,
            214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242,
            118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82,
            185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183,
            210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55,
            127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195,
            47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130,
            102, 75, 76, 15, 108, 196, 22, 89, 112, 124, 225, 37, 170, 121, 200, 204, 39, 82, 73, 239, 179, 79, 50, 51,
            207, 130, 16, 9, 49, 150, 137, 59, 156, 72, 231, 118, 10, 79, 87, 132, 54, 160, 121, 120, 82, 45, 130, 61,
            11, 207, 93, 176, 13, 49, 155, 223, 213, 26, 171, 188, 84, 184, 62, 16, 149, 16, 26, 35, 72, 12, 173, 68,
            176, 48, 84, 175, 37, 188, 209, 38, 57, 183, 57, 184, 123, 249, 56, 131, 229, 224, 39, 66, 9, 178, 36, 254,
            21, 73, 60, 212, 212, 119, 130, 245, 84, 33, 111, 156, 95, 19, 172, 13, 82, 37, 38, 109, 52, 223, 45, 162,
            130, 115, 64, 186, 53, 50, 42, 119, 173, 13, 128, 224, 12, 40, 93, 71, 136, 205, 137, 185, 138, 201, 202,
            158, 184, 18, 77, 242, 208, 18, 49, 124, 69, 105, 20, 3, 114, 204, 98, 30, 64, 153, 254, 165, 198, 129,
            124, 53, 251, 168, 187, 150, 176, 245, 34, 42, 159, 27, 186, 65, 126, 35, 175, 148, 173, 231, 57, 68, 198,
            175, 117, 130, 17, 248, 234, 224, 220, 238, 197, 226, 200, 190, 121, 5, 81, 66, 133, 13, 41, 74, 89, 29,
            106, 14, 56, 186, 246, 156, 51, 204, 84, 247, 202, 39, 58, 62, 38, 170, 170, 191, 8, 18, 15, 65, 53, 239,
            223, 98, 245, 69, 40, 70, 147, 81, 9, 177, 119, 78, 158, 68, 179, 94, 183, 150, 34, 134, 172, 28, 86, 63,
            192, 65, 4, 216,
        ];

        let public_key = compute_public_key("DH", Some(&SECRET_PARAMETERS_DH), PRIVATE_KEY_DH, PUBLIC_KEY_DH).unwrap();

        assert_eq!(expected_key[..], public_key[..]);
    }

    #[test]
    fn test_compute_kek_dh() {
        let expected_key = [
            9, 171, 213, 100, 174, 219, 112, 33, 135, 63, 151, 51, 231, 55, 121, 167, 132, 216, 251, 190, 174, 207,
            209, 164, 141, 125, 85, 196, 84, 60, 232, 36,
        ];

        let kek = compute_kek(
            HashAlg::Sha512,
            "DH",
            Some(SECRET_PARAMETERS_DH),
            PRIVATE_KEY_DH,
            PUBLIC_KEY_DH,
        )
        .unwrap();

        assert_eq!(expected_key[..], kek[..]);
    }

    #[test]
    fn test_cek_encrypt() {
        let expected_key = [
            177, 34, 69, 51, 190, 164, 94, 127, 38, 205, 148, 208, 11, 108, 215, 29, 178, 61, 153, 114, 42, 203, 15,
            82, 30, 72, 228, 118, 78, 34, 29, 117, 181, 56, 147, 124, 62, 48, 255, 39,
        ];

        let wrapped_key = cek_encrypt(
            &KeyEncryptionAlgorithmIdentifier::new_aes256_empty(AesMode::Wrap),
            &[
                9, 171, 213, 100, 174, 219, 112, 33, 135, 63, 151, 51, 231, 55, 121, 167, 132, 216, 251, 190, 174, 207,
                209, 164, 141, 125, 85, 196, 84, 60, 232, 36,
            ],
            &[
                206, 232, 113, 60, 84, 106, 53, 122, 24, 150, 171, 198, 170, 126, 87, 228, 7, 22, 212, 151, 162, 93,
                220, 211, 115, 74, 24, 231, 235, 112, 110, 133,
            ],
        )
        .unwrap();

        assert_eq!(expected_key[..], wrapped_key[..]);
    }

    #[test]
    fn test_cek_decrypt() {
        let expected_key = [
            237, 217, 97, 116, 100, 107, 229, 54, 97, 127, 233, 172, 141, 83, 124, 250, 21, 115, 218, 160, 137, 22,
            103, 96, 167, 25, 59, 35, 65, 126, 69, 192,
        ];

        let key = cek_decrypt(
            &KeyEncryptionAlgorithmIdentifier::new_aes256_empty(AesMode::Wrap),
            &[
                166, 59, 66, 26, 83, 122, 242, 219, 236, 155, 114, 107, 185, 13, 252, 191, 239, 219, 244, 91, 42, 197,
                34, 82, 11, 8, 251, 120, 137, 197, 250, 110,
            ],
            &[
                79, 59, 241, 186, 249, 240, 229, 63, 50, 183, 56, 137, 17, 64, 57, 136, 49, 12, 176, 219, 163, 106,
                132, 25, 1, 87, 85, 16, 179, 52, 21, 138, 173, 143, 110, 15, 16, 0, 99, 244,
            ],
        )
        .unwrap();

        assert_eq!(expected_key[..], key[..]);
    }

    const PLAINTEXT: &[u8] = &[84, 104, 101, 66, 101, 115, 116, 84, 118, 97, 114, 121, 110, 107, 97];
    const CIPHER_TEXT: &[u8] = &[
        141, 73, 82, 191, 110, 35, 212, 200, 182, 19, 135, 174, 143, 253, 167, 179, 170, 9, 181, 213, 130, 114, 20, 4,
        145, 63, 224, 92, 231, 37, 18,
    ];
    const AES256_GCM_IV: &[u8] = &[127, 98, 187, 173, 250, 133, 155, 4, 74, 60, 109, 245];
    const AES256_GCM_KEY: &[u8] = &[
        237, 217, 97, 116, 100, 107, 229, 54, 97, 127, 233, 172, 141, 83, 124, 250, 21, 115, 218, 160, 137, 22, 103,
        96, 167, 25, 59, 35, 65, 126, 69, 192,
    ];

    #[test]
    fn test_content_decrypt() {
        let plaintext = content_decrypt(
            &ContentEncryptionAlgorithmIdentifier::new_aes256(
                AesMode::Gcm,
                AesParameters::InitializationVector(OctetStringAsn1::from(AES256_GCM_IV.to_vec())),
            ),
            AES256_GCM_KEY,
            CIPHER_TEXT,
        )
        .unwrap();

        assert_eq!(PLAINTEXT[..], plaintext[..]);
    }

    #[test]
    fn test_content_encrypt() {
        let cipher_text = content_encrypt(
            &ContentEncryptionAlgorithmIdentifier::new_aes256(
                AesMode::Gcm,
                AesParameters::InitializationVector(OctetStringAsn1::from(AES256_GCM_IV.to_vec())),
            ),
            AES256_GCM_KEY,
            PLAINTEXT,
        )
        .unwrap();

        assert_eq!(CIPHER_TEXT[..], cipher_text[..]);
    }
}
