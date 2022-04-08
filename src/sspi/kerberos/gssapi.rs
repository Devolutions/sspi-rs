use std::{io::{Result, Error, ErrorKind, Read, Write}};

use byteorder::{WriteBytesExt, BigEndian, ReadBytesExt};

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
            return Err(Error::new(ErrorKind::InvalidData, "Invalid MIC token id"));
        }

        let flags = data.read_u8()?;

        let mut buf = [0, 0, 0, 0, 0];

        data.read_exact(&mut buf)?;
        if buf != MIC_FILLER {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid MIC Filler"));
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
        if buf != MIC_TOKEN_ID {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid MIC token id"));
        }

        let flags = data.read_u8()?;

        let mut buf = [0, 0, 0, 0, 0];

        data.read_exact(&mut buf)?;
        if buf != MIC_FILLER {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid MIC Filler"));
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
