use num_bigint_dig::BigUint;
use thiserror::Error;
use uuid::Uuid;

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
    // use rust_kbkdf::{CounterMode, kbkdf, KDFMode, InputType, CounterLocation, SpecifiedInput};

    // KDF(HashAlg, KI, Label, Context, L)
    // where KDF is SP800-108 in counter mode.
    let mut derived_key = [0; 32];

    // kbkdf(
    //     &KDFMode::CounterMode(CounterMode {
    //         length: 32,
    //     }),
    //     &InputType::FixedInput(SpecifiedInput {
    //         label,
    //         context,
    //     }),
    //     secret,
    //     prf,
    //     &mut derived_key,
    // )

    todo!()
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
