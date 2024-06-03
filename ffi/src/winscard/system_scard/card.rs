use std::borrow::Cow;
use std::mem::size_of;
use std::ptr::null_mut;
use std::slice::from_raw_parts;

use ffi_types::winscard::functions::SCardApiFunctionTable;
use ffi_types::winscard::{ScardContext, ScardHandle, ScardIoRequest};
use num_traits::ToPrimitive;
use winscard::winscard::{
    AttributeId, ControlCode, IoRequest, Protocol, ReaderAction, ShareMode, Status, TransmitOutData, WinScard,
};
use winscard::{Error, ErrorKind, WinScardResult};

use super::parse_multi_string_owned;
use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

pub struct SystemScard {
    h_card: ScardHandle,
    h_card_context: ScardContext,
    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
}

impl SystemScard {
    pub fn new(h_card: ScardHandle, h_card_context: ScardContext) -> Self {
        Self {
            h_card,
            h_card_context,
            #[cfg(target_os = "windows")]
            api: super::init_scard_api_table(),
        }
    }
}

impl Drop for SystemScard {
    fn drop(&mut self) {
        // The smart card handle can be explicitly disconnected before. So, there is no point
        // in double disconnecting.
        // Hint: It's always better to explicitly disconnect the card because the user can not pass
        // the custom `dwDisposition` parameter in `SCardDisconnect` function.
        if self.h_card != 0 {
            #[cfg(not(target_os = "windows"))]
            {
                if let Err(err) = try_execute!(unsafe { pcsc_lite_rs::SCardDisconnect(self.h_card, 0) }) {
                    error!(?err, "Cannot disconnect the card");
                }
            }
            #[cfg(target_os = "windows")]
            {
                if let Err(err) = try_execute!(unsafe { (self.api.SCardDisconnect)(self.h_card, 0) }) {
                    error!(?err, "Cannot disconnect the card");
                }
            }
        }
    }
}

impl WinScard for SystemScard {
    fn status(&self) -> WinScardResult<Status> {
        let mut reader_name: *mut u8 = null_mut();
        let mut reader_name_len = SCARD_AUTOALLOCATE;
        let mut state = 0;
        let mut protocol = 0;
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusw
        //
        // `pbAtr`: Pointer to a 32-byte buffer that receives the ATR string from the currently
        // inserted card, if available.
        //
        // PCSC-lite docs do not specify that ATR buf should be 32 bytes long, but actually,
        // the ATR string can not be longer than 32 bytes.
        let mut atr = vec![0; 32];
        let mut atr_len = 32;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#gae49c3c894ad7ac12a5b896bde70d0382
            //
            // If `*pcchReaderLen` is equal to SCARD_AUTOALLOCATE then the function will allocate itself
            // the needed memory for szReaderName. Use SCardFreeMemory() to release it.
            try_execute!(unsafe {
                pcsc_lite_rs::SCardStatus(
                    self.h_card,
                    (&mut reader_name as *mut *mut u8) as *mut _,
                    &mut reader_name_len,
                    &mut state,
                    &mut protocol,
                    atr.as_mut_ptr(),
                    &mut atr_len,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusa
            //
            // If this buffer length is specified as SCARD_AUTOALLOCATE, then szReaderName is converted to a pointer
            // to a byte pointer, and it receives the address of a block of memory that contains the multiple-string structure.
            try_execute!(unsafe {
                (self.api.SCardStatusA)(
                    self.h_card,
                    (&mut reader_name as *mut *mut u8) as *mut _,
                    &mut reader_name_len,
                    &mut state,
                    &mut protocol,
                    atr.as_mut_ptr(),
                    &mut atr_len,
                )
            })?;
            info!("atr after: {:?}", atr);
        }

        let readers = if let Ok(readers) =
            parse_multi_string_owned(unsafe { from_raw_parts(reader_name, reader_name_len.try_into()?) })
        {
            readers
        } else {
            #[cfg(not(target_os = "windows"))]
            {
                try_execute!(unsafe { pcsc_lite_rs::SCardFreeMemory(self.h_card_context, reader_name as *const _) })?;
            }
            #[cfg(target_os = "windows")]
            {
                try_execute!(unsafe { (self.api.SCardFreeMemory)(self.h_card_context, reader_name as *const _,) })?;
            }

            return Err(Error::new(
                ErrorKind::InternalError,
                "Returned reader is not valid UTF-8",
            ));
        };

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardFreeMemory(self.h_card_context, reader_name as *const _) })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardFreeMemory)(self.h_card_context, reader_name as *const _) })?;
        }

        let status = Status {
            readers,
            state: state.try_into()?,
            protocol: Protocol::from_bits(protocol).ok_or_else(|| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("Invalid protocol value: {}", protocol),
                )
            })?,
            atr: atr.into(),
        };

        Ok(status)
    }

    fn control(&mut self, code: ControlCode, input: &[u8], mut output: Option<&mut [u8]>) -> WinScardResult<usize> {
        let mut receive_len = 0;
        let (output_buf, output_buf_len) = if let Some(buf) = output.as_mut() {
            (buf.as_mut_ptr(), buf.len().try_into()?)
        } else {
            (null_mut(), 0)
        };

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardControl(
                    self.h_card,
                    code,
                    input.as_ptr() as *const _,
                    input.len().try_into()?,
                    output_buf as *mut _,
                    output_buf_len,
                    &mut receive_len,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                (self.api.SCardControl)(
                    self.h_card,
                    code,
                    input.as_ptr() as *const _,
                    input.len().try_into()?,
                    output_buf as *mut _,
                    output_buf_len,
                    &mut receive_len,
                )
            })?;
        }

        Ok(receive_len.try_into()?)
    }

    fn transmit(&mut self, send_pci: IoRequest, input_apdu: &[u8]) -> WinScardResult<TransmitOutData> {
        // The SCardTransmit function doesn't support SCARD_AUTOALLOCATE attribute. So, we need to allocate
        // the buffer for the output APDU by ourselves.
        // The `msclmd.dll` has `I_ClmdCmdExtendedTransmit` and `I_ClmdCmdShortTransmit` functions.
        // The first one uses 65538-bytes long buffer for output APDU, and the second one uses 258-bytes long buffer.
        // We decided to always use the larger one.
        const OUT_APDU_BUF_LEN: usize = 65538;

        #[cfg(not(target_os = "windows"))]
        type IoRequest = ScardIoRequest;
        #[cfg(target_os = "windows")]
        type IoRequest = windows_sys::Win32::Security::Credentials::SCARD_IO_REQUEST;

        // * https://learn.microsoft.com/en-us/windows/win32/secauthn/scard-io-request
        // * https://pcsclite.apdu.fr/api/structSCARD__IO__REQUEST.html#details
        //
        // The SCARD_IO_REQUEST structure begins a protocol control information structure.
        // Any protocol-specific information then immediately follows this structure.
        //
        // Length, in bytes, of the SCARD_IO_REQUEST structure plus any following PCI-specific information.
        let length = size_of::<ScardIoRequest>() + send_pci.pci_info.len();

        let mut scard_io_request = vec![0_u8; length];
        scard_io_request[size_of::<ScardIoRequest>()..].copy_from_slice(&send_pci.pci_info);

        let poi_send_pci = scard_io_request.as_mut_ptr() as *mut ScardIoRequest;

        let mut output_apdu_len = OUT_APDU_BUF_LEN.try_into()?;
        let mut output_apdu = [0; OUT_APDU_BUF_LEN];

        #[cfg(not(target_os = "windows"))]
        unsafe {
            (*poi_send_pci).dw_protocol = send_pci.protocol.bits();
            (*poi_send_pci).cb_pci_length = length.try_into()?;
        }

        #[cfg(target_os = "windows")]
        unsafe {
            (*poi_send_pci).dw_protocol = send_pci.protocol.bits();
            (*poi_send_pci).cb_pci_length = length.try_into()?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardTransmit(
                    self.h_card,
                    poi_send_pci,
                    input_apdu.as_ptr(),
                    input_apdu.len().try_into()?,
                    // https://pcsclite.apdu.fr/api/group__API.html#ga9a2d77242a271310269065e64633ab99
                    //
                    // pioRecvPci: This parameter can be NULL if no PCI is returned.
                    null_mut(),
                    output_apdu.as_mut_ptr(),
                    &mut output_apdu_len,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                (self.api.SCardTransmit)(
                    self.h_card,
                    poi_send_pci,
                    input_apdu.as_ptr(),
                    input_apdu.len().try_into()?,
                    // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardtransmit
                    //
                    // pioRecvPci: This parameter can be NULL if no PCI is returned.
                    null_mut(),
                    output_apdu.as_mut_ptr(),
                    &mut output_apdu_len,
                )
            })?;
        }

        Ok(TransmitOutData {
            output_apdu: output_apdu[0..output_apdu_len.try_into()?].to_vec(),
            receive_pci: None,
        })
    }

    fn begin_transaction(&mut self) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardBeginTransaction(self.h_card) })
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardBeginTransaction)(self.h_card) })
        }
    }

    fn end_transaction(&mut self, disposition: ReaderAction) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardEndTransaction(self.h_card, disposition.into()) })
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardEndTransaction)(self.h_card, disposition.into()) })
        }
    }

    fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocol: Option<Protocol>,
        initialization: ReaderAction,
    ) -> WinScardResult<Protocol> {
        let dw_preferred_protocols = preferred_protocol.unwrap_or_default().bits();
        let mut active_protocol = 0;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardReconnect(
                    self.h_card,
                    share_mode.into(),
                    dw_preferred_protocols,
                    initialization.into(),
                    &mut active_protocol,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                (self.api.SCardReconnect)(
                    self.h_card,
                    share_mode.into(),
                    dw_preferred_protocols,
                    initialization.into(),
                    &mut active_protocol,
                )
            })?;
        }

        Ok(Protocol::from_bits(active_protocol).unwrap_or_default())
    }

    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<Cow<[u8]>> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Cannot convert AttributeId -> u32"))?;
        let mut data_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602
            //
            // If this value is NULL, SCardGetAttrib() ignores the buffer length supplied in pcbAttrLen, writes the length of the buffer
            // that would have been returned if this parameter had not been NULL to pcbAttrLen, and returns a success code.
            try_execute!(unsafe { pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, null_mut(), &mut data_len) })?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib
            //
            // If this value is NULL, SCardGetAttrib ignores the buffer length supplied in pcbAttrLen,
            // writes the length of the buffer that would have been returned if this parameter
            // had not been NULL to pcbAttrLen, and returns a success code.
            try_execute!(unsafe { (self.api.SCardGetAttrib)(self.h_card, attr_id, null_mut(), &mut data_len,) })?;
        }

        let mut data = vec![0; data_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardGetAttrib(self.h_card, attr_id, data.as_mut_ptr(), &mut data_len)
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardGetAttrib)(self.h_card, attr_id, data.as_mut_ptr(), &mut data_len) })?;
        }

        Ok(Cow::Owned(data))
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Cannot convert AttributeId -> u32"))?;

        let len = attribute_data.len().try_into()?;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardSetAttrib(self.h_card, attr_id, attribute_data.as_ptr(), len) })
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardSetAttrib)(self.h_card, attr_id, attribute_data.as_ptr(), len,) })
        }
    }

    fn disconnect(&mut self, disposition: ReaderAction) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardDisconnect(self.h_card, disposition.into()) })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { (self.api.SCardDisconnect)(self.h_card, disposition.into()) })?;
        }

        // Mark the current card handle as disconnected.
        self.h_card = 0;

        Ok(())
    }
}
