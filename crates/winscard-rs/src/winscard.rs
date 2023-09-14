use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::WinScardResult as Result;

pub type Atr = [u8; 32];

pub struct Icon(Vec<u8>);

impl AsRef<[u8]> for Icon {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ShareMode {
    Shared,
    Exclusive,
    Direct,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    T0,
    T1,
    Raw,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Absent,
    Present,
    Swallowed,
    Powered,
    Negotiable,
    Specific,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub readers: Vec<String>,
    pub state: State,
    pub protocol: Protocol,
    pub atr: Atr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlCode {
    Ctl = 0x00313520,
}

#[derive(Debug, Clone)]
pub struct IoRequest {
    pub protocol: Protocol,
    pub pci_info: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TransmitOutData {
    pub output_apdu: Vec<u8>,
    pub receive_pci: Option<IoRequest>,
}

pub trait WinScard {
    fn status(&self) -> Result<Status>;
    fn control(&mut self, code: ControlCode, input: &[u8]) -> Result<Vec<u8>>;
    fn transmit(&mut self, send_pci: IoRequest, input_apdu: &[u8]) -> Result<TransmitOutData>;
    fn begin_transaction(&mut self) -> Result<()>;
    fn end_transaction(&mut self) -> Result<()>;
}

pub trait WinScardContext {
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> Result<Box<dyn WinScard>>;
    fn list_readers(&self) -> Vec<String>;
    fn device_type_id(&self, reader_name: &str) -> Result<u32>;
    fn reader_icon(&self, reader_name: &str) -> Result<Icon>;
    fn is_valid(&self) -> bool;
}
