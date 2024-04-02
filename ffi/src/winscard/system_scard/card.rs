use winscard::winscard::{
    AttributeId, ControlCode, IoRequest, Protocol, ReconnectInitialization, ShareMode, Status, TransmitOutData,
    WinScard,
};
use winscard::WinScardResult;

pub struct SystemScard {}

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
        todo!()
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
