use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::sspi::ntlm::messages::{read_ntlm_header, try_read_version, MessageFields, MessageTypes};
use crate::sspi::ntlm::{NegotiateFlags, NegotiateMessage, Ntlm, NtlmState};
use crate::sspi::{self, SecurityStatus};

const HEADER_SIZE: usize = 32;

pub fn read_negotiate(context: &mut Ntlm, mut stream: impl io::Read) -> sspi::Result<SecurityStatus> {
    check_state(context.state)?;

    let mut buffer = Vec::with_capacity(HEADER_SIZE);
    stream.read_to_end(&mut buffer)?;
    let mut buffer = io::Cursor::new(buffer);

    read_ntlm_header(&mut buffer, MessageTypes::Negotiate)?;
    context.flags = read_header(&mut buffer)?;
    let _version = try_read_version(context.flags, &mut buffer)?;

    let message = buffer.into_inner();
    context.negotiate_message = Some(NegotiateMessage::new(message));

    context.state = NtlmState::Challenge;

    Ok(sspi::SecurityStatus::ContinueNeeded)
}

fn check_state(state: NtlmState) -> sspi::Result<()> {
    if state != NtlmState::Negotiate {
        Err(sspi::Error::new(
            sspi::ErrorKind::OutOfSequence,
            String::from("Read negotiate was fired but the state is not a Negotiate"),
        ))
    } else {
        Ok(())
    }
}

fn read_header(mut buffer: impl io::Read) -> sspi::Result<NegotiateFlags> {
    let mut domain_name = MessageFields::new();
    let mut workstation = MessageFields::new();

    let negotiate_flags =
        NegotiateFlags::from_bits(buffer.read_u32::<LittleEndian>()?).unwrap_or_else(NegotiateFlags::empty);

    if !negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_REQUEST_TARGET)
        || !negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_NTLM)
        || !negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_UNICODE)
    {
        return Err(sspi::Error::new(
            sspi::ErrorKind::InvalidToken,
            String::from("Negotiate flags do not contain the necessary flags"),
        ));
    }

    domain_name.read_from(&mut buffer)?;
    workstation.read_from(&mut buffer)?;

    Ok(negotiate_flags)
}
