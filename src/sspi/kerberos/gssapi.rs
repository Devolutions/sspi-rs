use std::io::{Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kerberos_crypto::{checksum_sha_aes, AesSizes};
use picky_krb::constants::key_usages::INITIATOR_SIGN;

use crate::sspi::{Error, ErrorKind, Result};

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
            return Err(Error::new(ErrorKind::InvalidToken, "Invalid MIC token id".into()));
        }

        let flags = data.read_u8()?;

        let mut buf = [0, 0, 0, 0, 0];

        data.read_exact(&mut buf)?;
        if buf != MIC_FILLER {
            return Err(Error::new(ErrorKind::InvalidToken, "Invalid MIC Filler".into()));
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
            return Err(Error::new(ErrorKind::InvalidToken, "Invalid WRAP token id".into()));
        }

        let flags = data.read_u8()?;

        let filler = data.read_u8()?;
        if filler != WRAP_FILLER {
            return Err(Error::new(ErrorKind::InvalidToken, "Invalid Wrap Filler".into()));
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
