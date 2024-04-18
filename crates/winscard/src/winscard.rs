use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};

use crate::{Error, ErrorKind, WinScardResult};

/// Type alias used to represent memory address.
pub type MemoryPtr = usize;
/// Control code for the `SCardControl` operation.
///
/// This value identifies the specific operation to be performed. More info:
/// * [WinSCard SCardControl](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcontrol)
/// * [pcsc-lite SCardControl](https://pcsclite.apdu.fr/api/group__API.html#gac3454d4657110fd7f753b2d3d8f4e32f)
pub type ControlCode = u32;

/// Action to be taken on the reader.
///
/// More info:
/// * [SCardEndTransaction](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardendtransaction).
/// * [SCardReconnect](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreconnect).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum ReaderAction {
    /// Do not do anything special.
    LeaveCard = 0,
    /// Reset the card.
    ResetCard = 1,
    /// Power down the card.
    UnpowerCard = 2,
    /// Eject the card.
    EjectCard = 3,
}

impl TryFrom<u32> for ReaderAction {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => ReaderAction::LeaveCard,
            1 => ReaderAction::ResetCard,
            2 => ReaderAction::UnpowerCard,
            3 => ReaderAction::EjectCard,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!("Gow invalid disposition value: {}", value),
                ))
            }
        })
    }
}

impl From<ReaderAction> for u32 {
    fn from(value: ReaderAction) -> Self {
        value as u32
    }
}

/// A smart card attribute id.
///
/// This enum represents a scard attribute id. A set of variants is formed by merging `WinSCard` attr ids and `pscsc-lite` attr ids.
/// More info:
/// * [WinSCard SCardGetAttrib](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib).
/// * [pcsc-lite SCardGetAttrib](https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum AttributeId {
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a2e87e6925548b9fcca3fa0026b82500d
    AsyncProtocolTypes = 0x0120,
    /// Answer to reset (ATR) string.
    AtrString = 0x0303,
    /// Channel id.
    ///
    /// See [SCardGetAttrib](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib) for more details.
    ChannelId = 0x0110,
    /// DWORD indicating which mechanical characteristics are supported. If zero, no special characteristics are supported.
    Characteristics = 0x0150,
    /// Current block waiting time.
    CurrentBwt = 0x0209,
    /// Current clock rate, in kHz.
    CurrentClk = 0x0202,
    /// Current character waiting time.
    CurrentCwt = 0x020a,
    /// Bit rate conversion factor.
    CurrentD = 0x0204,
    /// Current error block control encoding.
    CurrentEbcEncoding = 0x020b,
    /// Clock conversion factor.
    CurrentF = 0x0203,
    /// Current byte size for information field size card.
    CurrentIfsc = 0x0207,
    /// Current byte size for information field size device.
    CurrentIfsd = 0x0208,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a9c6ee3dccc23e924907e3dc2e29a50f6
    CurrentIoState = 0x0302,
    /// Current guard time.
    CurrentN = 0x0205,
    /// DWORD encoded as 0x0rrrpppp where rrr is RFU and should be 0x000. pppp encodes the current protocol type.
    /// Whichever bit has been set indicates which ISO protocol is currently in use. (For example, if bit zero is set,
    /// T=0 protocol is in effect.)
    CurrentProtocolType = 0x0201,
    /// Current work waiting time.
    CurrentW = 0x0206,
    /// Default clock rate, in kHz.
    DefaultClk = 0x0121,
    /// Default data rate, in bps.
    DefaultDataRate = 0x0123,
    /// Reader's display name.
    DeviceFriendlyName = 0x0003,
    /// Reader's display name but encoded in Wide string.
    DeviceFriendlyNameW = 0x0005,
    /// Reserved for future use.
    DeviceInUse = 0x0002,
    /// Reader's system name.
    DeviceSystemName = 0x0004,
    /// Reader's system name.
    DeviceSystemNameW = 0x0006,
    /// Instance of this vendor's reader attached to the computer. The first instance will be device unit 0,
    /// the next will be unit 1 (if it is the same brand of reader) and so on. Two different brands of readers
    /// will both have zero for this value.
    DeviceUnit = 0x0001,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a1a1d31628ec9f49f79d2dda6651658d6
    EscAuhRequest = 0xA005,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a69d8dd84f5f433efbfa6e0fce2a95528
    EscCancel = 0xA003,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a55df7896fb65a2a942780d383d815071
    EscReset = 0xA000,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a5fcd5c979018130c164a64c728f0716d
    ExtendedBt = 0x020c,
    /// Single byte. Zero if smart card electrical contact is not active; nonzero if contact is active.
    IccInterfaceStatus = 0x0301,
    /// Single byte indicating smart card presence.
    IccPresence = 0x0300,
    /// Single byte indicating smart card type.
    IccTypePerAtr = 0x0304,
    /// Maximum clock rate, in kHz.
    MaxClk = 0x0122,
    /// Maximum data rate, in bps.
    MaxDataRate = 0x0124,
    /// Maximum bytes for information file size device.
    MaxIfsd = 0x0125,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a42ea634deb1ec51e10722b661aa73d01
    MaxInput = 0xA007,
    /// Zero if device does not support power down while smart card is inserted. Nonzero otherwise.
    PowerMgmtSupport = 0x0131,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a62d09db2a45663ea726239aeafaac747
    SupresT1IfsRequest = 0x0007,
    /// DWORD encoded as 0x0rrrpppp where rrr is RFU and should be 0x000. pppp encodes the supported
    /// protocol types. A '1' in a given bit position indicates support for the associated ISO protocol,
    /// so if bits zero and one are set, both T=0 and T=1 protocols are supported.
    SyncProtocolTypes = 0x0126,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a86eb3bba6a8a463aa0eac4ada7704785
    UserAuthInputDevice = 0x0142,
    /// https://pcsclite.apdu.fr/api/reader_8h.html#a60bf2dbb950d448099314aa86c14b2aa
    UserToCardAuthDevice = 0x0140,
    /// Vendor-supplied interface device serial number.
    VendorIfdSerialNo = 0x0103,
    /// Vendor-supplied interface device type (model designation of reader).
    VendorIfdType = 0x0101,
    /// Vendor-supplied interface device version (DWORD in the form 0xMMmmbbbb where MM = major version,
    /// mm = minor version, and bbbb = build number).
    VendorIfdVersion = 0x0102,
    /// Vendor name.
    VendorName = 0x0100,
}

/// ATR string.
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
#[repr(u32)]
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

impl From<DeviceTypeId> for u32 {
    fn from(value: DeviceTypeId) -> Self {
        value as u32
    }
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

impl From<ShareMode> for u32 {
    fn from(value: ShareMode) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for ShareMode {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Exclusive),
            2 => Ok(Self::Shared),
            3 => Ok(Self::Direct),
            _ => Err(Error::new(
                ErrorKind::InvalidParameter,
                format!("Invalid ShareMode value: {}", value),
            )),
        }
    }
}

bitflags! {
    /// [SCardConnectW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnectw)
    ///
    /// `dwPreferredProtocols` and `pdwActiveProtocol` parameters:
    /// A bitmask of acceptable protocols for the connection.
    /// Possible values may be combined with the OR operation.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
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
#[repr(u32)]
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

impl From<State> for u32 {
    fn from(value: State) -> Self {
        value as u32
    }
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
    fn control(&mut self, code: ControlCode, input: &[u8], output: Option<&mut [u8]>) -> WinScardResult<usize>;

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
    fn end_transaction(&mut self, disposition: ReaderAction) -> WinScardResult<()>;

    /// [SCardReconnect](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreconnect)
    ///
    /// The SCardReconnect function reestablishes an existing connection between the calling application and a smart card.
    /// This function moves a card handle from direct access to general access, or acknowledges and clears an error condition that is preventing further access to the card.
    fn reconnect(
        &mut self,
        share_mode: ShareMode,
        preferred_protocol: Option<Protocol>,
        initialization: ReaderAction,
    ) -> WinScardResult<Protocol>;

    /// [SCardGetAttrib](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib)
    ///
    /// The SCardGetAttrib function retrieves the current reader attributes for the given handle.
    /// It does not affect the state of the reader, driver, or card.
    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<Cow<[u8]>>;

    /// [SCardSetAttrib](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardsetattrib)
    ///
    /// The SCardSetAttrib function sets the given reader attribute for the given handle. It does not affect
    /// the state of the reader, reader driver, or smart card. Not all attributes are supported
    /// by all readers (nor can they be set at all times) as many of the attributes are under direct control of the transport protocol.
    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()>;
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

    /// [SCardListReaderGroupsW](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadergroupsw)
    ///
    /// The SCardListReaderGroups function provides the list of reader groups that have previously been introduced to the system.
    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<str>>>;

    /// [SCardCancel](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcancel)
    ///
    /// The SCardCancel function terminates all outstanding actions within a specific resource manager context.
    /// The only requests that you can cancel are those that require waiting for external action by the smart card or user.
    /// Any such outstanding action requests will terminate with a status indication that the action was canceled.
    fn cancel(&mut self) -> WinScardResult<()>;

    /// [SCardFreeMemory](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardfreememory)
    ///
    /// The SCardFreeMemory function releases memory that has been returned from the resource manager
    /// using the `SCARD_AUTOALLOCATE` length designator.
    fn free(&mut self, ptr: MemoryPtr) -> WinScardResult<()>;
}
