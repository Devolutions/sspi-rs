use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;

use crate::{Error, ErrorKind, WinScardResult};

/// ATR string
///
/// A sequence of bytes returned from a smart card when it is turned on.
/// These bytes are used to identify the card to the system.
///
/// [SCardStatusW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusw)
/// `pbAtr` parameter:
/// A 32-byte buffer that holds the ATR string from the currently inserted card.
/// Note: 32 is a maximum ATR string len. In reality, the original Windows TPM smart card always returns 17-bytes len ATR string.
#[derive(Debug, Clone)]
pub struct Atr(Vec<u8>);

impl AsRef<[u8]> for Atr {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for Atr {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<[u8; 17]> for Atr {
    fn from(value: [u8; 17]) -> Self {
        Self(value.into())
    }
}

/// A buffer that contains a BLOB of the smart card reader icon as read from the icon file.
#[derive(Debug, Clone)]
pub struct Icon<'a>(Cow<'a, [u8]>);

impl<'a> AsRef<[u8]> for Icon<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for Icon<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl From<Vec<u8>> for Icon<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self(Cow::Owned(value))
    }
}

/// [SCardGetDeviceTypeIdW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetdevicetypeidw)
/// The actual device type identifier. The list of reader types returned
/// by this function are listed under ReaderType member in the SCARD_READER_CAPABILITIES structure.
///
/// [SCARD_READER_CAPABILITIES](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/smclib/ns-smclib-_scard_reader_capabilities)
/// `ReaderType` parameter:
/// This member contains the reader type and is required. This member can have one of the values in the following table.
#[derive(Debug, Copy, Clone)]
pub enum DeviceTypeId {
    /// Serial reader
    Serial = 0x01,
    /// Parallel reader
    Paralell = 0x02,
    /// Keyboard-attached reader
    Keyboard = 0x04,
    /// SCSI reader
    Scsi = 0x08,
    /// IDE reader
    Ide = 0x10,
    /// USB reader
    Usb = 0x20,
    /// PCMCIA reader
    Pcmcia = 0x40,
    /// Reader that uses a TPM chip for key material storage and cryptographic operations
    Tpm = 0x80,
    /// Reader that uses a proprietary vendor bus
    Vendor = 0xf0,
}

/// [SCardConnectW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnectw)
///
/// `dwShareMode` parameter:
/// A flag that indicates whether other applications may form connections to the card.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ShareMode {
    /// This application is not willing to share the card with other applications.
    Exclusive = 1,
    /// This application is willing to share the card with other applications.
    Shared = 2,
    /// This application is allocating the reader for its private use, and will be controlling it directly.
    /// No other applications are allowed access to it.
    Direct = 3,
}

bitflags! {
    /// [SCardConnectW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnectw)
    ///
    /// `dwPreferredProtocols` and `pdwActiveProtocol` parameters:
    /// A bitmask of acceptable protocols for the connection.
    /// Possible values may be combined with the OR operation.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct Protocol: u32 {
        /// This parameter may be zero only if dwShareMode is set to SCARD_SHARE_DIRECT.
        /// In this case, no protocol negotiation will be performed by the drivers
        /// until an IOCTL_SMARTCARD_SET_PROTOCOL control directive is sent with SCardControl.
        const UNDEFINED = 0x00000000;
        /// The ISO 7816/3 T=0 protocol is in use.
        /// An asynchronous, character-oriented half-duplex transmission protocol.
        const T0 = 0x00000001;
        /// The ISO 7816/3 T=1 protocol is in use.
        /// An asynchronous, block-oriented half-duplex transmission protocol.
        const T1 = 0x00000002;
        /// The Raw Transfer protocol is in use.
        /// This flags can be used **only** in the `SCardStatusA/W` function in the `pdwProtocol` parameter.
        const Raw = 0x00010000;
    }
}

/// [SCardStatusW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusw)
///
/// `pdwState` parameter:
/// Current state of the smart card in the reader. Upon success, it receives one of the following state indicators.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    /// Unknown smart card status.
    Unknown = 0,
    /// There is no card in the reader.
    Absent = 1,
    /// There is a card in the reader, but it has not been moved into position for use.
    Present = 2,
    /// There is a card in the reader in position for use. The card is not powered.
    Swallowed = 3,
    /// Power is being provided to the card, but the reader driver is unaware of the mode of the card.
    Powered = 4,
    /// The card has been reset and is awaiting PTS negotiation.
    Negotiable = 5,
    /// The card has been reset and specific communication protocols have been established.
    Specific = 6,
}

/// This structure described the current status and basic info about the smart card reader.
#[derive(Debug, Clone)]
pub struct Status<'a> {
    /// List of display names (multiple string) by which the currently connected reader is known.
    pub readers: Vec<Cow<'a, str>>,
    /// Current state of the smart card in the reader
    pub state: State,
    /// Current protocol, if any. The returned value is meaningful only if the returned value of pdwState is SCARD_SPECIFICMODE.
    pub protocol: Protocol,
    /// Buffer that receives the ATR string from the currently inserted card, if available.
    /// [ATR string](https://learn.microsoft.com/en-us/windows/win32/secgloss/a-gly)
    pub atr: Atr,
}

/// [SCardControl](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcontrol)
///
/// `dwControlCode` parameter:
/// Control code for the operation. This value identifies the specific operation to be performed.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlCode {
    /// `#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)`
    /// Request features described in the *PC/SC 2.0 Specification Part 10*
    IoCtl = 0x00313520,
}

impl TryFrom<u32> for ControlCode {
    type Error = Error;

    fn try_from(value: u32) -> WinScardResult<Self> {
        match value {
            0x00313520 => Ok(ControlCode::IoCtl),
            _ => Err(Error::new(
                ErrorKind::InvalidParameter,
                format!("Unsupported control code: {:x?}", value),
            )),
        }
    }
}

/// [SCARD_IO_REQUEST](https://learn.microsoft.com/en-us/windows/win32/secauthn/scard-io-request)
///
/// The SCARD_IO_REQUEST structure begins a protocol control information structure.
/// Any protocol-specific information then immediately follows this structure.
///
/// ```not_rust
/// typedef struct {
///   DWORD dwProtocol;
///   DWORD cbPciLength;
/// } SCARD_IO_REQUEST;
/// ```
#[derive(Debug, Clone)]
pub struct IoRequest {
    /// Protocol in use.
    pub protocol: Protocol,
    /// PCI-specific information.
    pub pci_info: Vec<u8>,
}

/// This structure represents the result of the `SCardTransmit` function.
#[derive(Debug, Clone)]
pub struct TransmitOutData {
    /// Data returned from the card. If no data is returned from the card,
    /// then this buffer will only contain the SW1 and SW2 status bytes.
    pub output_apdu: Vec<u8>,
    /// Returned protocol control information (PCI) specific to the protocol in use.
    pub receive_pci: Option<IoRequest>,
}

/// This trait provides interface for all available smart card related functions in the `winscard.h`.
///
/// # MSDN
///
/// * [winscard.h](https://learn.microsoft.com/en-us/windows/win32/api/winscard/)
pub trait WinScard {
    /// [SCardStatusW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusw)
    ///
    /// The SCardStatus function provides the current status of a smart card in a reader.
    /// You can call it any time after a successful call to `SCardConnect` and before a successful
    /// call to `SCardDisconnect`. It does not affect the state of the reader or reader driver.
    fn status(&self) -> WinScardResult<Status>;

    /// [SCardControl](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcontrol)
    ///
    /// The SCardControl function gives you direct control of the reader.
    /// You can call it any time after a successful call to SCardConnect and before a successful call to SCardDisconnect.
    /// The effect on the state of the reader depends on the control code.
    fn control(&mut self, code: ControlCode, input: &[u8]) -> WinScardResult<Vec<u8>>;

    /// [SCardTransmit](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardtransmit)
    ///
    /// The SCardTransmit function sends a service request to the smart card and expects to receive data back from the card.
    fn transmit(&mut self, send_pci: IoRequest, input_apdu: &[u8]) -> WinScardResult<TransmitOutData>;

    /// [SCardBeginTransaction](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardbegintransaction)
    ///
    /// The SCardBeginTransaction function starts a transaction.
    /// The function waits for the completion of all other transactions before it begins.
    /// After the transaction starts, all other applications are blocked from accessing the smart card while the transaction is in progress.
    fn begin_transaction(&mut self) -> WinScardResult<()>;

    /// [SCardEndTransaction](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardendtransaction)
    ///
    /// The SCardEndTransaction function completes a previously declared transaction,
    /// allowing other applications to resume interactions with the card.
    fn end_transaction(&mut self) -> WinScardResult<()>;
}

/// This trait provides interface for all available smart card context (resource manager) related
/// functions in the `winscard.h`.
///
/// # MSDN
///
/// * [winscard.h](https://learn.microsoft.com/en-us/windows/win32/api/winscard/)
pub trait WinScardContext {
    /// [SCardConnectW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnectw)
    ///
    /// The SCardConnect function establishes a connection (using a specific resource manager context) between
    /// the calling application and a smart card contained by a specific reader.
    /// If no card exists in the specified reader, an error is returned.
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<Box<dyn WinScard>>;

    /// [SCardListReadersW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadersw)
    ///
    /// Provides the list of readers within a set of named reader groups, eliminating duplicates.
    fn list_readers(&self) -> Vec<Cow<str>>;

    /// [SCardGetDeviceTypeIdW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetdevicetypeidw)
    ///
    /// Gets the device type identifier of the card reader for the given reader name.
    /// This function does not affect the state of the reader.
    fn device_type_id(&self, reader_name: &str) -> WinScardResult<DeviceTypeId>;

    /// [SCardGetReaderIconW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetreadericonw)
    ///
    /// The SCardGetReaderIcon function gets an icon of the smart card reader for a given reader's name.
    /// This function does not affect the state of the card reader.
    fn reader_icon(&self, reader_name: &str) -> WinScardResult<Icon>;

    /// [SCardIsValidContext](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardisvalidcontext)
    ///
    /// The SCardIsValidContext function determines whether a smart card context handle is valid.
    fn is_valid(&self) -> bool;

    /// [SCardReadCacheW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreadcachew)
    ///
    /// The SCardReadCache function retrieves the value portion of a name-value pair from the global cache maintained by the Smart Card Resource Manager.
    fn read_cache(&self, key: &str) -> Option<&[u8]>;

    /// [SCardWriteCacheW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardwritecachew)
    ///
    /// The SCardWriteCache function writes a name-value pair from a smart card to the global cache maintained by the Smart Card Resource Manager.
    fn write_cache(&mut self, key: String, value: Vec<u8>);
}
