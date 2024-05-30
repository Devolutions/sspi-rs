#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(target_os = "windows")]
compile_error!("The pcsc-lite-rs crate should be used only on Linux/MacOS. Use windows/windows-sys crated to interact with Windows API.");

use ffi_types::winscard::{ScardIoRequest, ScardReaderStateA, ScardStatus};
use ffi_types::{Dword, LpByte, LpCByte, LpCStr, LpCVoid, LpDword, LpStr, LpVoid};

/// `hContext` returned by `SCardEstablishContext()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#a22530ffaff18b5d3e32260a5f1ce4abd
pub type ScardContext = i32;
/// Pointer to the [ScardContext].
pub type LpScardContext = *mut ScardContext;

/// `hCard` returned by `SCardConnect()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#af328aca3e11de737ecd771bcf1f75fb5
pub type ScardHandle = i32;
/// Pointer to the [ScardHandle].
pub type LpScardHandle = *mut ScardHandle;

extern "system" {
    /// Creates an Application Context to the PC/SC Resource Manager.
    ///
    /// [SCardEstablishContext](https://pcsclite.apdu.fr/api/group__API.html#gaa1b8970169fd4883a6dc4a8f43f19b67)
    /// This must be the first WinSCard function called in a PC/SC application. Each thread of an application shall use its own `SCARDCONTEXT`,
    /// unless calling `SCardCancel()`, which MUST be called with the same context as the context used to call `SCardGetStatusChange()`.
    pub fn SCardEstablishContext(
        dw_scope: Dword,
        pv_reserved_1: LpVoid,
        pv_reserved_2: LpVoid,
        ph_context: LpScardContext,
    ) -> ScardStatus;

    /// Destroys a communication context to the PC/SC Resource Manager.
    ///
    /// [SCardReleaseContext](https://pcsclite.apdu.fr/api/group__API.html#ga6aabcba7744c5c9419fdd6404f73a934)
    /// This must be the last function called in a PC/SC application.
    pub fn SCardReleaseContext(h_context: ScardContext) -> ScardStatus;

    /// Establishes a connection to the reader specified in * szReader.
    ///
    /// [SCardConnect](https://pcsclite.apdu.fr/api/group__API.html#ga4e515829752e0a8dbc4d630696a8d6a5)
    pub fn SCardConnect(
        h_context: ScardContext,
        sz_reader: LpCStr,
        dw_share_mode: Dword,
        dw_preferred_protocols: Dword,
        ph_card: LpScardHandle,
        pdw_active_protocol: LpDword,
    ) -> ScardStatus;

    /// Reestablishes a connection to a reader that was previously connected to using `SCardConnect()`.
    ///
    /// [SCardReconnect](https://pcsclite.apdu.fr/api/group__API.html#gad5d4393ca8c470112ad9468c44ed8940)
    /// In a multi application environment it is possible for an application to reset the card in shared mode.
    /// When this occurs any other application trying to access certain commands will be returned the value `SCARD_W_RESET_CARD`.
    /// When this occurs `SCardReconnect()` must be called in order to acknowledge that the card was reset and allow it to change its state accordingly.
    pub fn SCardReconnect(
        h_card: ScardHandle,
        dw_share_mode: Dword,
        dw_preferred_protocols: Dword,
        dw_initialization: Dword,
        pdw_active_protocol: LpDword,
    ) -> ScardStatus;

    /// Terminates a connection made through SCardConnect().
    ///
    /// [SCardDisconnect](https://pcsclite.apdu.fr/api/group__API.html#ga4be198045c73ec0deb79e66c0ca1738a)
    pub fn SCardDisconnect(h_card: ScardHandle, dw_disposition: Dword) -> ScardStatus;

    /// Establishes a temporary exclusive access mode for doing a series of commands in a transaction.
    ///
    /// [SCardBeginTransaction](https://pcsclite.apdu.fr/api/group__API.html#gaddb835dce01a0da1d6ca02d33ee7d861)
    /// You might want to use this when you are selecting a few files and then writing a large file,
    /// so you can make sure that another application will not change the current file. If another application has a lock on this reader
    /// or this application is in `SCARD_SHARE_EXCLUSIVE` the function will block until it can continue.
    pub fn SCardBeginTransaction(h_card: ScardHandle) -> ScardStatus;

    /// Ends a previously begun transaction.
    ///
    /// [SCardEndTransaction](https://pcsclite.apdu.fr/api/group__API.html#gae8742473b404363e5c587f570d7e2f3b)
    /// The calling application must be the owner of the previously begun transaction or an error will occur.
    pub fn SCardEndTransaction(h_card: ScardHandle, dw_disposition: Dword) -> ScardStatus;

    /// Returns the current status of the reader connected to by hCard.
    ///
    /// [SCardStatus](https://pcsclite.apdu.fr/api/group__API.html#gae49c3c894ad7ac12a5b896bde70d0382)
    pub fn SCardStatus(
        h_card: ScardHandle,
        sz_reader_name: LpStr,
        pcch_reader_len: LpDword,
        pdw_state: LpDword,
        pdw_protocol: LpDword,
        pb_atr: LpByte,
        pcb_atr_len: LpDword,
    ) -> ScardStatus;

    /// Blocks execution until the current availability of the cards in a specific set of readers changes.
    ///
    /// [SCardGetStatusChange](https://pcsclite.apdu.fr/api/group__API.html#ga33247d5d1257d59e55647c3bb717db24)
    pub fn SCardGetStatusChange(
        h_context: ScardContext,
        dw_timeout: Dword,
        rg_reader_states: *mut ScardReaderStateA,
        c_readers: Dword,
    ) -> ScardStatus;

    /// Sends a command directly to the IFD Handler (reader driver) to be processed by the reader.
    ///
    /// [SCardControl](https://pcsclite.apdu.fr/api/group__API.html#gac3454d4657110fd7f753b2d3d8f4e32f)
    /// This is useful for creating client side reader drivers for functions like PIN pads, biometrics,
    /// or other extensions to the normal smart card reader that are not normally handled by PC/SC.
    pub fn SCardControl(
        h_card: ScardHandle,
        dw_control_code: Dword,
        pb_send_buffer: LpCVoid,
        cb_send_length: Dword,
        pb_recv_buffer: LpVoid,
        cb_recv_length: Dword,
        lp_bytes_returned: LpDword,
    ) -> ScardStatus;

    /// Get an attribute from the IFD Handler (reader driver).
    ///
    /// [SCardGetAttrib](https://pcsclite.apdu.fr/api/group__API.html#gaacfec51917255b7a25b94c5104961602)
    pub fn SCardGetAttrib(h_card: ScardHandle, dw_attr_id: Dword, pb_attr: LpByte, pcb_atr_len: LpDword)
        -> ScardStatus;

    /// Set an attribute of the IFD Handler.
    ///
    /// [SCardSetAttrib](https://pcsclite.apdu.fr/api/group__API.html#ga060f0038a4ddfd5dd2b8fadf3c3a2e4f)
    pub fn SCardSetAttrib(h_card: ScardHandle, dw_attr_id: Dword, pb_attr: LpCByte, cb_attr_len: Dword) -> ScardStatus;

    /// Sends an APDU to the smart card contained in the reader connected to by `SCardConnect()`.
    ///
    /// [SCardTransmit](https://pcsclite.apdu.fr/api/group__API.html#ga9a2d77242a271310269065e64633ab99)
    pub fn SCardTransmit(
        h_card: ScardHandle,
        poi_send_pci: *const ScardIoRequest,
        pb_send_buffer: LpCByte,
        cb_send_length: Dword,
        poi_recv_pci: *mut ScardIoRequest,
        pb_recv_buffer: LpByte,
        pcb_recv_length: LpDword,
    ) -> ScardStatus;

    /// Returns a list of currently available readers on the system.
    ///
    /// [SCardListReaders](https://pcsclite.apdu.fr/api/group__API.html#ga93b07815789b3cf2629d439ecf20f0d9)
    pub fn SCardListReaders(
        h_context: ScardContext,
        msz_groups: LpCStr,
        msc_reader: LpStr,
        pcch_readers: LpDword,
    ) -> ScardStatus;

    /// Releases memory that has been returned from the resource manager using the `SCARD_AUTOALLOCATE` length designator.
    ///
    /// [SCardFreeMemory](https://pcsclite.apdu.fr/api/group__API.html#ga0522241e3180cb05dfd166e28930e961)
    pub fn SCardFreeMemory(h_context: ScardContext, pv_mem: LpCVoid) -> ScardStatus;

    /// Returns a list of currently available reader groups on the system.
    ///
    /// [SCardListReaderGroups](https://pcsclite.apdu.fr/api/group__API.html#ga9d970d086d5218e080d0079d63f9d496)
    pub fn SCardListReaderGroups(h_context: ScardContext, msz_groups: LpStr, pcch_groups: LpDword) -> ScardStatus;

    /// Cancels a specific blocking `SCardGetStatusChange()` function.
    ///
    /// [SCardCancel](https://pcsclite.apdu.fr/api/group__API.html#gaacbbc0c6d6c0cbbeb4f4debf6fbeeee6)
    /// MUST be called with the same `SCARDCONTEXT` as `SCardGetStatusChange()`.
    pub fn SCardCancel(h_context: ScardContext) -> ScardStatus;

    /// Check if a [ScardContext] is valid.
    ///
    /// [SCardIsValidContext](https://pcsclite.apdu.fr/api/group__API.html#ga722eb66bcc44d391f700ff9065cc080b).
    /// Call this function to determine whether a smart card context handle is still valid. After a smart card context handle
    /// has been returned by `SCardEstablishContext()`, it may become invalid if the resource manager service has been shut down.
    pub fn SCardIsValidContext(h_context: ScardContext) -> ScardStatus;
}
