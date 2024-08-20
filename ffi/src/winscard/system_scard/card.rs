use std::borrow::Cow;
use std::mem::size_of;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::io::Write;

#[cfg(target_os = "windows")]
use ffi_types::winscard::functions::SCardApiFunctionTable;
use ffi_types::winscard::ScardIoRequest;
#[cfg(target_os = "windows")]
use ffi_types::winscard::{ScardContext, ScardHandle};
use num_traits::ToPrimitive;
use winscard::winscard::{
    AttributeId, ControlCode, IoRequest, Protocol, ReaderAction, ShareMode, Status, TransmitOutData, WinScard,
};
use winscard::{Error, ErrorKind, WinScardResult};

use super::parse_multi_string_owned;
use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::{initialize_pcsc_lite_api, ScardContext, ScardHandle};

/// Represents a state of the current `SystemScard`.
#[derive(Copy, Clone, Debug)]
enum HandleState {
    /// The card is not connected or has been disconnected.
    Disconnected,
    /// The card is connected and ready to use.
    Connected(ScardHandle),
}

/// Represents a system-provided smart card.
///
/// _Hint:_ It's **always better** to explicitly disconnect the card using the [SystemScard::disconnect] method.
/// Otherwise, the card will be disconnected automatically on the drop. But in such a case,
/// the user is unable to pass the custom `dwDisposition` parameter in `SCardDisconnect` function.
pub struct SystemScard {
    h_card: HandleState,
    h_card_context: ScardContext,
    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    api: PcscLiteApiFunctionTable,
}

use std::fmt;

impl fmt::Debug for SystemScard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemScard")
         .field("h_card", &self.h_card)
         .field("h_card_context", &self.h_card_context)
         .finish()
    }
}

impl SystemScard {
    /// Creates a new instance of the [SystemScard].
    ///
    /// _Note._ `h_card` and `h_card_context` parameters (handles) must be initialized using
    /// the corresponding methods.
    pub fn new(h_card: ScardHandle, h_card_context: ScardContext) -> WinScardResult<Self> {
        if h_card == 0 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "scard handle can not be a zero",
            ));
        }

        if h_card_context == 0 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "scard context handle can not be a zero",
            ));
        }

        Ok(Self {
            h_card: HandleState::Connected(h_card),
            h_card_context,
            #[cfg(target_os = "windows")]
            api: super::init_scard_api_table()?,
            #[cfg(not(target_os = "windows"))]
            api: initialize_pcsc_lite_api()?,
        })
    }

    fn h_card(&self) -> WinScardResult<ScardHandle> {
        if let HandleState::Connected(handle) = self.h_card {
            Ok(handle)
        } else {
            Err(Error::new(
                ErrorKind::InvalidHandle,
                "smart card is not connected or has been disconnected",
            ))
        }
    }
}

impl Drop for SystemScard {
    fn drop(&mut self) {
        if let HandleState::Connected(handle) = self.h_card {
            if let Err(err) = try_execute!(
                // SAFETY: This function is safe to call because the `handle` is valid.
                unsafe { (self.api.SCardDisconnect)(handle, 0) }
            ) {
                error!(?err, "Failed to disconnect the card");
            }
        }
    }
}

impl WinScard for SystemScard {
    #[instrument(ret)]
    fn status(&self) -> WinScardResult<Status> {
        println!("status status status");
        debug!("status status status");

        let mut reader_name = [0_u8; 1024];
        let mut reader_name_len = 1024;
        let mut state = 0xdead_beef;
        let mut protocol = 0xdead_beef;
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusw
        //
        // `pbAtr`: Pointer to a 32-byte buffer that receives the ATR string from the currently
        // inserted card, if available.
        //
        // PCSC-lite docs do not specify that ATR buf should be 32 bytes long, but actually,
        // the ATR string can not be longer than 32 bytes.
        let mut atr = [0_u8; 32];
        let mut atr_len = 32;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#gae49c3c894ad7ac12a5b896bde70d0382
            //
            // If `*pcchReaderLen` is equal to SCARD_AUTOALLOCATE then the function will allocate itself
            // the needed memory for szReaderName. Use SCardFreeMemory() to release it.
            debug!(atr_len, reader_name_len);
            let res = try_execute!(
                // SAFETY: This function is safe to call because `self.h_card` is checked
                // and all other values is type checked.
                unsafe {
                    (self.api.SCardStatus)(
                        self.h_card()?,
                        reader_name.as_mut_ptr(),
                        &mut reader_name_len,
                        &mut state,
                        &mut protocol,
                        atr.as_mut_ptr(),
                        &mut atr_len,
                    )
                },
                "SCardStatus failed"
            );
            debug!(?res, atr_len, reader_name_len);
            res?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusa
            // If this buffer length is specified as SCARD_AUTOALLOCATE, then szReaderName is converted to a pointer
            // to a byte pointer, and it receives the address of a block of memory that contains the multiple-string structure.
            //
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and all other values is type checked.
            try_execute!(
                // SAFETY: This function is safe to call because `self.h_card` is checked
                // and all other values is type checked.
                unsafe {
                    (self.api.SCardStatusA)(
                        self.h_card()?,
                        (&mut reader_name as *mut *mut u8) as *mut _,
                        &mut reader_name_len,
                        &mut state,
                        &mut protocol,
                        atr.as_mut_ptr(),
                        &mut atr_len,
                    )
                },
                "SCardStatusA failed"
            )?;
        }

        debug!(reader_name_len);
        println!("{} status status status", reader_name_len);
        std::io::stdout().flush().unwrap();

        // SAFETY: A slice creation is safe in this context because the `reader_name` pointer is
        // a local pointer that was initialized by the `SCardStatus` function.
        // let multi_string_buffer = unsafe { from_raw_parts(reader_name, reader_name_len.try_into()?) };
        let multi_string_buffer = &reader_name[0..reader_name_len.try_into()?];
        debug!(?multi_string_buffer);
        println!("{:?}", multi_string_buffer);
        let readers = if let Ok(readers) = parse_multi_string_owned(multi_string_buffer) {
            readers
        } else {
            // try_execute!(
            //     // SAFETY: This function is safe to call because `self.h_card_context` is always a valid handle.
            //     unsafe { (self.api.SCardFreeMemory)(self.h_card_context, reader_name as *const _) },
            //     "SCardFreeMemory failed"
            // )?;

            return Err(Error::new(
                ErrorKind::InternalError,
                "returned reader is not valid UTF-8",
            ));
        };

        // try_execute!(
        //     // SAFETY: This function is safe to call because `self.h_card_context` is always a valid handle.
        //     unsafe { (self.api.SCardFreeMemory)(self.h_card_context, reader_name as *const _) },
        //     "SCardFreeMemory failed"
        // )?;

        let state_b = crate::winscard::pcsc_lite::State::from_bits(state);
        debug!(state, ?state_b);

        let status = Status {
            readers,
            state: state_b.map(|s| s.into()).unwrap_or(winscard::winscard::State::Specific),
            protocol: Protocol::from_bits(protocol.try_into().unwrap()).ok_or_else(|| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("Invalid protocol value: {}", protocol),
                )
            })?,
            atr: atr[0..atr_len.try_into()?].to_vec().into(),
        };

        Ok(status)
    }

    fn control(&mut self, code: ControlCode, input: &[u8]) -> WinScardResult<()> {
        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe {
                (self.api.SCardControl)(
                    self.h_card()?,
                    code.into(),
                    input.as_ptr() as *const _,
                    input.len().try_into()?,
                    null_mut(),
                    0,
                    null_mut(),
                )
            },
            "SCardControl failed"
        )?;

        Ok(())
    }

    fn control_with_output(&mut self, code: ControlCode, input: &[u8], output: &mut [u8]) -> WinScardResult<usize> {
        let mut receive_len = 0;
        let output_buf_len = output.len().try_into()?;

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe {
                (self.api.SCardControl)(
                    self.h_card()?,
                    code.into(),
                    input.as_ptr() as *const _,
                    input.len().try_into()?,
                    output.as_mut_ptr() as *mut _,
                    output_buf_len,
                    &mut receive_len,
                )
            },
            "SCardControl failed"
        )?;

        Ok(receive_len.try_into()?)
    }

    fn transmit(&mut self, send_pci: IoRequest, input_apdu: &[u8]) -> WinScardResult<TransmitOutData> {
        // The SCardTransmit function doesn't support SCARD_AUTOALLOCATE attribute. So, we need to allocate
        // the buffer for the output APDU by ourselves.
        // The `msclmd.dll` has `I_ClmdCmdExtendedTransmit` and `I_ClmdCmdShortTransmit` functions.
        // The first one uses 65538-bytes long buffer for output APDU, and the second one uses 258-bytes long buffer.
        // We decided to always use the larger one.
        const OUT_APDU_BUF_LEN: usize = 65538;

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

        // SAFETY: The `poi_send_pci` pointer is created from the local allocated memory and should
        // be valid in the current context.
        unsafe {
            (*poi_send_pci).dw_protocol = send_pci.protocol.bits();
            (*poi_send_pci).cb_pci_length = length.try_into()?;
        }

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe {
                (self.api.SCardTransmit)(
                    self.h_card()?,
                    poi_send_pci,
                    input_apdu.as_ptr(),
                    input_apdu.len().try_into()?,
                    // https://pcsclite.apdu.fr/api/group__API.html#ga9a2d77242a271310269065e64633ab99
                    // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardtransmit
                    //
                    // pioRecvPci: This parameter can be NULL if no PCI is returned.
                    null_mut(),
                    output_apdu.as_mut_ptr(),
                    &mut output_apdu_len,
                )
            },
            "SCardTransmit failed"
        )?;

        Ok(TransmitOutData {
            output_apdu: output_apdu[0..output_apdu_len.try_into()?].to_vec(),
            receive_pci: None,
        })
    }

    fn begin_transaction(&mut self) -> WinScardResult<()> {
        debug!("TBT: scardbt: {} - {}. {} - {}", self.h_card()?, std::mem::size_of::<ScardHandle>(), self.h_card_context, std::mem::size_of::<ScardContext>());

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked.
            unsafe { (self.api.SCardBeginTransaction)(self.h_card()?) },
            "SCardBeginTransaction failed"
        )
    }

    fn end_transaction(&mut self, disposition: ReaderAction) -> WinScardResult<()> {
        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and the `disposition` parameter is type checked.
            unsafe { (self.api.SCardEndTransaction)(self.h_card()?, disposition.into()) },
            "SCardEndTransaction failed"
        )
    }

    fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocol: Option<Protocol>,
        initialization: ReaderAction,
    ) -> WinScardResult<Protocol> {
        let dw_preferred_protocols = preferred_protocol.unwrap_or_default().bits();
        let mut active_protocol = 0;

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe {
                (self.api.SCardReconnect)(
                    self.h_card()?,
                    share_mode.into(),
                    dw_preferred_protocols.into(),
                    initialization.into(),
                    &mut active_protocol,
                )
            },
            "SCardReconnect failed"
        )?;

        Ok(Protocol::from_bits(active_protocol.try_into().unwrap()).unwrap_or_default())
    }

    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<Cow<[u8]>> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "cannot convert AttributeId -> u32"))?;
        let mut data_len = 0;

        // https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602
        // If this value is NULL, SCardGetAttrib() ignores the buffer length supplied in pcbAttrLen, writes the length of the buffer
        // that would have been returned if this parameter had not been NULL to pcbAttrLen, and returns a success code.
        //
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib
        // If this value is NULL, SCardGetAttrib ignores the buffer length supplied in pcbAttrLen,
        // writes the length of the buffer that would have been returned if this parameter
        // had not been NULL to pcbAttrLen, and returns a success code.
        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe { (self.api.SCardGetAttrib)(self.h_card()?, attr_id.into(), null_mut(), &mut data_len) },
            "SCardGetAttrib failed"
        )?;

        let mut data = vec![0; data_len.try_into()?];

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe { (self.api.SCardGetAttrib)(self.h_card()?, attr_id.into(), data.as_mut_ptr(), &mut data_len) },
            "SCardGetAttrib failed"
        )?;

        Ok(Cow::Owned(data))
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        let attr_id = attribute_id
            .to_u32()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "cannot convert AttributeId -> u32"))?;

        let len = attribute_data.len().try_into()?;

        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is checked
            // and other function parameters are type checked.
            unsafe { (self.api.SCardSetAttrib)(self.h_card()?, attr_id.into(), attribute_data.as_ptr(), len) },
            "SCardSetAttrib failed"
        )
    }

    fn disconnect(&mut self, disposition: ReaderAction) -> WinScardResult<()> {
        try_execute!(
            // SAFETY: This function is safe to call because `self.h_card` is always a valid handle
            // and the `disposition` parameter is type checked.
            unsafe { (self.api.SCardDisconnect)(self.h_card()?, disposition.into()) },
            "SCardDisconnect failed"
        )?;

        // Mark the current card handle as disconnected.
        self.h_card = HandleState::Disconnected;

        Ok(())
    }
}
