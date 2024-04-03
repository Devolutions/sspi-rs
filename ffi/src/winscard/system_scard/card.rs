use ffi_types::winscard::ScardHandle;
use num_traits::FromPrimitive;
use winscard::winscard::{
    AttributeId, ControlCode, IoRequest, Protocol, ReconnectInitialization, ShareMode, Status, TransmitOutData,
    WinScard,
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

    fn end_transaction(&mut self) -> WinScardResult<()> {
        todo!()
    }

    fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocol: Option<Protocol>,
        initialization: ReconnectInitialization,
    ) -> WinScardResult<Protocol> {
        todo!()
    }

    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<&[u8]> {
        todo!()
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        todo!()
    }
}
