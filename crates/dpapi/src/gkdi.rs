use byteorder::{LittleEndian, ReadBytesExt};
use dpapi_core::gkdi::{GkdiError, GroupKeyEnvelope, KdfParameters, KDF_ALGORITHM_NAME, KeyIdentifier};
use dpapi_core::rpc::SyntaxId;
use dpapi_core::{Decode, ReadCursor};
use rand::rngs::OsRng;
use rand::Rng;
use uuid::uuid;

use crate::crypto::{
    compute_kek, compute_kek_from_public_key, compute_l2_key, compute_public_key, kdf, KDS_SERVICE_LABEL,
};
use crate::Result;

pub const ISD_KEY: SyntaxId = SyntaxId {
    uuid: uuid!("b9785960-524f-11df-8b6d-83dcded72085"),
    version: 1,
    version_minor: 0,
};

/// Checks the RPC GetKey Response status (`hresult`) and tries to parse the data into [GroupKeyEnvelope].
pub fn unpack_response(data: &[u8]) -> Result<GroupKeyEnvelope> {
    if data.len() < 4 {
        Err(GkdiError::BadResponse("response data length is too small"))?;
    }
    let (key_buf, mut hresult_buf) = data.split_at(data.len() - 4);

    let hresult = hresult_buf.read_u32::<LittleEndian>()?;
    if hresult != 0 {
        Err(GkdiError::BadHresult(hresult))?;
    }

    let mut src = ReadCursor::new(key_buf);

    let _key_length = src.read_u32();
    // Skip padding
    src.read_u32();

    // Skip the referent id and double up on pointer size
    src.read_u64();
    src.read_u64();

    Ok(GroupKeyEnvelope::decode_cursor(&mut src)?)
}

pub fn new_kek(group_key: &GroupKeyEnvelope) -> Result<(Vec<u8>, KeyIdentifier)> {
    if group_key.kdf_alg != KDF_ALGORITHM_NAME {
        Err(GkdiError::InvalidKdfAlgName {
            expected: KDF_ALGORITHM_NAME,
            actual: group_key.kdf_alg.clone(),
        })?;
    }

    let kdf_parameters = KdfParameters::decode(group_key.kdf_parameters.as_slice())?;
    let hash_alg = kdf_parameters.hash_alg;

    let mut rand = OsRng;

    let (kek, key_info) = if group_key.is_public_key() {
        // the L2 key is the peer's public key

        let mut private_key = vec![group_key.private_key_length.div_ceil(8).try_into()?];
        rand.fill(private_key.as_mut_slice());

        let kek = compute_kek(hash_alg, &group_key.secret_algorithm, &private_key, &group_key.l2_key)?;
        let key_info = compute_public_key(&group_key.secret_algorithm, &private_key, &group_key.l2_key)?;

        (kek, key_info)
    } else {
        let key_info = rand.gen::<[u8; 32]>();
        let kek = kdf(hash_alg, &group_key.l2_key, KDS_SERVICE_LABEL, &key_info, 32)?;

        (kek, key_info.to_vec())
    };

    Ok((
        kek,
        KeyIdentifier {
            version: 1,
            flags: group_key.flags,

            l0: group_key.l0,
            l1: group_key.l1,
            l2: group_key.l2,
            root_key_identifier: group_key.root_key_identifier,

            key_info,
            domain_name: group_key.domain_name.clone(),
            forest_name: group_key.forest_name.clone(),
        },
    ))
}

pub fn get_kek(group_key: &GroupKeyEnvelope, key_identifier: &KeyIdentifier) -> Result<Vec<u8>> {
    if group_key.is_public_key() {
        Err(GkdiError::IsNotAuthorized)?;
    }

    if group_key.l0 != key_identifier.l0 {
        Err(GkdiError::InvalidL0Index)?;
    }

    if group_key.kdf_alg != KDF_ALGORITHM_NAME {
        Err(GkdiError::InvalidKdfAlgName {
            expected: KDF_ALGORITHM_NAME,
            actual: group_key.kdf_alg.clone(),
        })?;
    }

    let kdf_parameters = KdfParameters::decode(group_key.kdf_parameters.as_slice())?;
    let hash_alg = kdf_parameters.hash_alg;
    let l2_key = compute_l2_key(hash_alg, key_identifier.l1, key_identifier.l2, group_key)?;

    if key_identifier.is_public_key() {
        Ok(compute_kek_from_public_key(
            hash_alg,
            &l2_key,
            &group_key.secret_algorithm,
            &key_identifier.key_info,
            group_key.private_key_length.div_ceil(8).try_into()?,
        )?)
    } else {
        Ok(kdf(hash_alg, &l2_key, KDS_SERVICE_LABEL, &key_identifier.key_info, 32)?)
    }
}
