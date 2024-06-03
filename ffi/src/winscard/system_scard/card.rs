use std::ptr::null_mut;

use ffi_types::winscard::ScardHandle;
use num_traits::{FromPrimitive, ToPrimitive};
use winscard::winscard::{
    AttributeId, ControlCode, IoRequest, OutBuffer, Protocol, ReaderAction, RequestedBufferType, ShareMode, Status,
    TransmitOutData, WinScard,
};
use winscard::{Error, ErrorKind, WinScardResult};

pub struct SystemScard {
    h_card: ScardHandle,
}

impl SystemScard {
    pub fn new(h_card: ScardHandle) -> Self {
        Self { h_card }
    }
}

impl WinScard for SystemScard {
    fn status(&self) -> WinScardResult<Status> {
        todo!()
    }

    fn control(&mut self, code: ControlCode, input: &[u8]) -> WinScardResult<Vec<u8>> {
        todo!()
    }

    fn transmit(&mut self, send_pci: IoRequest, input_apdu: &[u8]) -> WinScardResult<TransmitOutData> {
        todo!()
    }

    fn begin_transaction(&mut self) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        unsafe {
            try_execute!(pcsc_lite_rs::SCardBeginTransaction(self.h_card))?;
        }
        // TODO(@TheBestTvarynka): implement for Windows too.
        Ok(())
    }

    fn end_transaction(&mut self, disposition: ReaderAction) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        unsafe {
            try_execute!(pcsc_lite_rs::SCardEndTransaction(self.h_card, disposition.into()))?;
        }
        // TODO(@TheBestTvarynka): implement for Windows too.
        Ok(())
    }

    fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocol: Option<Protocol>,
        initialization: ReaderAction,
    ) -> WinScardResult<Protocol> {
        #[cfg(not(target_os = "windows"))]
        {
            let dw_preferred_protocols = preferred_protocol.unwrap_or_default().bits();
            let mut active_protocol = 0;

            try_execute!(unsafe {
                pcsc_lite_rs::SCardReconnect(
                    self.h_card,
                    share_mode.into(),
                    dw_preferred_protocols,
                    initialization.into(),
                    &mut active_protocol,
                )
            })?;

            Ok(Protocol::from_bits(active_protocol).unwrap_or_default())
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
    }

    fn get_attribute(&self, attribute_id: AttributeId, buffer_type: RequestedBufferType) -> WinScardResult<OutBuffer> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Cannot convert AttributeId -> u32"))?;

        #[cfg(not(target_os = "windows"))]
        {
            Ok(match buffer_type {
                RequestedBufferType::Length => {
                    let mut data_len = 0;

                    // [SCardGetAttrib](https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602)
                    //
                    // If this value is NULL, SCardGetAttrib() ignores the buffer length supplied in pcbAttrLen, writes the length of the buffer
                    // that would have been returned if this parameter had not been NULL to pcbAttrLen, and returns a success code.
                    try_execute!(unsafe {
                        pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, null_mut(), &mut data_len)
                    })?;

                    OutBuffer::DataLen(data_len.try_into()?)
                }
                RequestedBufferType::Buff(buf) => {
                    let mut data_len = buf.len().try_into()?;

                    try_execute!(unsafe {
                        pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, buf.as_mut_ptr(), &mut data_len)
                    })?;

                    OutBuffer::Written(data_len.try_into()?)
                }
                RequestedBufferType::Allocate => {
                    let mut data_len = 0;

                    // [SCardGetAttrib](https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602)
                    //
                    // If this value is NULL, SCardGetAttrib() ignores the buffer length supplied in pcbAttrLen, writes the length of the buffer
                    // that would have been returned if this parameter had not been NULL to pcbAttrLen, and returns a success code.
                    try_execute!(unsafe {
                        pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, null_mut(), &mut data_len)
                    })?;

                    let mut data = vec![0; data_len.try_into().unwrap()];
                    try_execute!(unsafe {
                        pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, data.as_mut_ptr(), &mut data_len)
                    })?;

                    OutBuffer::Allocated(data)
                }
            })
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Cannot convert AttributeId -> u32"))?;

        #[cfg(not(target_os = "windows"))]
        {
            let len = attribute_data.len().try_into().unwrap();
            try_execute!(unsafe { pcsc_lite_rs::SCardSetAttrib(self.h_card, attr_id, attribute_data.as_ptr(), len) })?;
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
        }
        Ok(())
    }
}
