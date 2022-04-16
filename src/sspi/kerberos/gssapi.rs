use std::io::{Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kerberos_crypto::{checksum_sha_aes, AesSizes};
use picky_krb::constants::key_usages::INITIATOR_SIGN;

use crate::sspi::{Error, ErrorKind, Result};

use super::{negotiate::get_mech_list, EncryptionParams};

const MIC_TOKEN_ID: [u8; 2] = [0x04, 0x04];
const MIC_FILLER: [u8; 5] = [0xff, 0xff, 0xff, 0xff, 0xff];

const WRAP_TOKEN_ID: [u8; 2] = [0x05, 0x04];
const WRAP_FILLER: [u8; 2] = [0xff, 0xff];

pub struct MicToken {
    pub flags: u8,
    pub seq_num: u64,
    pub payload: Option<Vec<u8>>,
    pub checksum: Vec<u8>,
}

impl MicToken {
    pub fn encode(&self, mut data: impl Write) -> Result<()> {
        data.write_all(&MIC_TOKEN_ID)?;
        data.write_u8(self.flags)?;
        data.write_all(&MIC_FILLER)?;
        data.write_u64::<BigEndian>(self.seq_num)?;
        data.write_all(&self.checksum)?;

        Ok(())
    }

    pub fn decode(mut data: impl Read) -> Result<Self> {
        let mut buf = [0, 0];

        data.read_exact(&mut buf)?;
        if buf != MIC_TOKEN_ID {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "Invalid MIC token id".into(),
            ));
        }

        let flags = data.read_u8()?;

        let mut buf = [0, 0, 0, 0, 0];

        data.read_exact(&mut buf)?;
        if buf != MIC_FILLER {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "Invalid MIC Filler".into(),
            ));
        }

        let seq_num = data.read_u64::<BigEndian>()?;

        let mut checksum = Vec::with_capacity(12);
        data.read_to_end(&mut checksum)?;

        Ok(Self {
            flags,
            seq_num,
            checksum,
            payload: None
        })
    }

    pub fn generate_initiator_raw(
        mut payload: Vec<u8>,
        seq_number: u64,
        session_key: &[u8],
    ) -> Vec<u8> {
        let mut mic_token = Self::with_initiator_flags().with_seq_number(seq_number);

        payload.extend_from_slice(&mic_token.header());

        mic_token.set_checksum(checksum_sha_aes(
            session_key,
            INITIATOR_SIGN,
            &payload,
            &AesSizes::Aes256,
        ));

        let mut mic_token_raw = Vec::new();
        mic_token.encode(&mut mic_token_raw).unwrap();

        mic_token_raw
    }
}

pub fn validate_mic_token(
    raw_token: &[u8],
    key_usage: i32,
    params: &EncryptionParams,
) -> Result<()> {
    let token = MicToken::decode(raw_token)?;

    let mut payload = picky_asn1_der::to_vec(&get_mech_list()).unwrap();
    payload.extend_from_slice(&token.header());

    let key = if let Some(key) = params.sub_session_key.as_ref() {
        key
    } else if let Some(key) = params.sub_session_key.as_ref() {
        key
    } else {
        return Err(Error {
            error_type: ErrorKind::DecryptFailure,
            description: "unable to obtain decryption key".into(),
        });
    };

    let checksum = checksum_sha_aes(
        &key,
        key_usage,
        &payload,
        &params.aes_sizes().unwrap_or(AesSizes::Aes256),
    );

    if checksum != token.checksum {
        return Err(Error {
            error_type: ErrorKind::MessageAltered,
            description: "bad checksum of the mic token".into(),
        });
    }

    Ok(())
}

#[derive(Debug)]
pub struct WrapToken {
    pub flags: u8,
    pub ec: u16,
    pub rrc: u16,
    pub seq_num: u64,
    pub payload: Option<Vec<u8>>,
    pub checksum: Vec<u8>,
}

impl WrapToken {
    pub fn encode(&self, mut data: impl Write) -> Result<()> {
        data.write_all(&WRAP_TOKEN_ID)?;
        data.write_u8(self.flags)?;
        data.write_all(&WRAP_FILLER)?;
        data.write_u16::<BigEndian>(self.ec)?;
        data.write_u16::<BigEndian>(self.rrc)?;
        data.write_u64::<BigEndian>(self.seq_num)?;
        data.write_all(&self.checksum)?;

        Ok(())
    }

    pub fn decode(mut data: impl Read) -> Result<Self> {
        let mut buf = [0, 0];

        data.read_exact(&mut buf)?;
        if buf != WRAP_TOKEN_ID {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "Invalid WRAP token id".into(),
            ));
        }

        let flags = data.read_u8()?;

        let filler = data.read_u8()?;
        if filler != WRAP_FILLER {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "Invalid Wrap Filler".into(),
            ));
        }

        let ec = data.read_u16::<BigEndian>()?;
        let rrc = data.read_u16::<BigEndian>()?;
        let seq_num = data.read_u64::<BigEndian>()?;

        let mut checksum = Vec::with_capacity(12);
        data.read_to_end(&mut checksum)?;

        Ok(Self {
            flags,
            ec,
            rrc,
            seq_num,
            checksum,
            payload: None,
        })
    }
}
