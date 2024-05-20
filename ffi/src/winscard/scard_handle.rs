use std::iter::once;
use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{LpScardIoRequest, ScardContext, ScardHandle, ScardIoRequest};
use ffi_types::LpCVoid;
use winscard::winscard::{AttributeId, IoRequest, Protocol, State, Uuid, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

/// Scard context handle representation.
///
/// Additionally, it holds allocated buffers and created smart card handles.
/// We need them because during the smart card context deletion, we need to free all allcated resources.
pub struct WinScardContextHandle {
    /// Context of the emulated smart card.
    scard_context: Box<dyn WinScardContext>,
    /// Created smart card handles during the API usage.
    scards: Vec<ScardHandle>,
    /// Allocated buffers in our smart card context.
    /// All buffers are `[u8]`, so we need only pointer and don't need to remember its type.
    allocations: Vec<usize>,
}

impl WinScardContextHandle {
    /// Creates a new [WinScardContextHandle] based on the provided inner scard context.
    pub fn with_scard_context(scard_context: Box<dyn WinScardContext>) -> Self {
        Self {
            scard_context,
            scards: Vec::new(),
            allocations: Vec::new(),
        }
    }

    /// Returns the shared reference to the inner [WinScardContext].
    pub fn scard_context(&self) -> &dyn WinScardContext {
        self.scard_context.as_ref()
    }

    /// Adds a new [ScardHandle] to the context handles.
    pub fn add_scard(&mut self, scard: ScardHandle) -> WinScardResult<()> {
        if scard == 0 {
            return Err(Error::new(ErrorKind::InvalidHandle, "ScardHandle can not be NULL"));
        }

        info!("Add new scard context: {}", scard);

        self.scards.push(scard);

        Ok(())
    }

    /// Removes the [ScardHandle] from the scard context.
    pub fn remove_scard(&mut self, scard: ScardHandle) -> bool {
        if let Some(index) = self.scards.iter().position(|x| *x == scard) {
            self.scards.remove(index);

            true
        } else {
            false
        }
    }

    /// Allocated a new buffer inside the scard context.
    pub fn allocate_buffer(&mut self, size: usize) -> WinScardResult<*mut u8> {
        let buff = unsafe { libc::malloc(size) as *mut u8 };
        if buff.is_null() {
            return Err(Error::new(
                ErrorKind::NoMemory,
                format!("Can not allocate {} bytes", size),
            ));
        }
        self.allocations.push(buff as usize);

        Ok(buff)
    }

    /// Deletes the buffer inside the scard context.
    pub fn free_buffer(&mut self, buff: LpCVoid) -> bool {
        let buff = buff as usize;

        if let Some(index) = self.allocations.iter().position(|x| *x == buff) {
            self.allocations.remove(index);

            unsafe {
                libc::free(buff as _);
            }

            true
        } else {
            false
        }
    }

    /// Returns the icon of the specified reader.
    pub fn get_reader_icon(&mut self, reader: &str, buffer_type: RequestedBufferType) -> WinScardResult<OutBuffer> {
        let reader_icon = self.scard_context.reader_icon(reader)?.as_ref().to_vec();

        self.write_to_out_buf(&reader_icon, buffer_type)
    }

    /// Lists readers.
    pub fn list_readers(&mut self, buffer_type: RequestedBufferType) -> WinScardResult<OutBuffer> {
        let readers: Vec<_> = self
            .scard_context()
            .list_readers()?
            .into_iter()
            .map(|i| i.to_string())
            .collect();

        self.write_multi_string(&readers, buffer_type)
    }

    /// Lists readers but the resulting buffers contain wide strings.
    pub fn list_readers_wide(&mut self, buffer_type: RequestedBufferType) -> WinScardResult<OutBuffer> {
        let readers: Vec<_> = self
            .scard_context()
            .list_readers()?
            .into_iter()
            .map(|i| i.to_string())
            .collect();

        self.write_multi_string_wide(&readers, buffer_type)
    }

    /// Reads smart card cache.
    pub fn read_cache(
        &mut self,
        card_id: Uuid,
        freshness_counter: u32,
        key: &str,
        buffer_type: RequestedBufferType,
    ) -> WinScardResult<OutBuffer> {
        let cached_value = self
            .scard_context()
            .read_cache(card_id, freshness_counter, key)?
            .to_vec();

        self.write_to_out_buf(cached_value.as_ref(), buffer_type)
    }

    /// Converts provided strings to the C-multi-string and saves it.
    pub fn write_multi_string(
        &mut self,
        values: &[String],
        buffer_type: RequestedBufferType,
    ) -> WinScardResult<OutBuffer<'static>> {
        let data: Vec<_> = values
            .iter()
            .flat_map(|reader| reader.as_bytes().iter().cloned().chain(once(0)))
            .chain(once(0))
            .collect();

        self.write_to_out_buf(&data, buffer_type)
    }

    /// Converts provided strings to the C-multi-string and saves it but the resulting buffers contain
    /// wide strings.
    pub fn write_multi_string_wide(
        &mut self,
        values: &[String],
        buffer_type: RequestedBufferType,
    ) -> WinScardResult<OutBuffer<'static>> {
        let data: Vec<_> = values
            .iter()
            .flat_map(|reader| {
                reader
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .flat_map(|i| i.to_le_bytes().to_vec())
            })
            .chain([0, 0].into_iter())
            .collect();

        debug!(?data);

        self.write_to_out_buf(&data, buffer_type)
    }

    /// Saves the provided data in the [OutBuffer] based on the [RequestedBufferType].
    pub fn write_to_out_buf(
        &mut self,
        data: &[u8],
        buffer_type: RequestedBufferType,
    ) -> WinScardResult<OutBuffer<'static>> {
        Ok(match buffer_type {
            RequestedBufferType::Buff(buf) => {
                if buf.len() < data.len() {
                    return Err(
                        Error::new(
                            ErrorKind::InsufficientBuffer, format!(
                                "Provided buffer is too small to fill the requested attribute into. Buffer len: {}. Attribute data len: {}.",
                                buf.len(),
                                data.len()
                            )
                        )
                    );
                }

                buf[0..data.len()].copy_from_slice(&data);

                OutBuffer::Written(data.len())
            }
            RequestedBufferType::Length => OutBuffer::DataLen(data.len()),
            RequestedBufferType::Allocate => {
                let allocated = self.allocate_buffer(data.len())?;
                let buf = unsafe { from_raw_parts_mut(allocated, data.len()) };

                buf.copy_from_slice(&data);

                OutBuffer::Allocated(buf)
            }
        })
    }
}

impl Drop for WinScardContextHandle {
    fn drop(&mut self) {
        // [SCardReleaseContext](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreleasecontext)
        // ...freeing any resources allocated under that context, including SCARDHANDLE objects
        trace!("scards to disconnect: {:?}", self.scards);
        unsafe {
            for scard in &self.scards {
                let _ = Box::from_raw(*scard as *mut WinScardHandle);
            }
        }
        // ...and memory allocated using the SCARD_AUTOALLOCATE length designator.
        unsafe {
            for buff in &self.allocations {
                libc::free(*buff as _);
            }
        }
    }
}

/// Represents how and what data the user want to extract.
pub enum RequestedBufferType<'data> {
    /// This means the user wants the data filled in the provided buffer.
    Buff(&'data mut [u8]),
    /// The user want to query only the data length.
    Length,
    /// The user wants the data to be allocated by the library and returned from the function.
    Allocate,
}

/// Represent the requested data buffer from the smart card.
///
/// The user can request some data from the smart card. For example, `SCardReadCache` or `SCardGetAttrib` functions.
/// However, buffer handling can be tricky in such situations. The user may want to allocate the memory
/// or ask us to do it. This enum aimed to solve this complexity.
pub enum OutBuffer<'data> {
    /// The data has been written into provided buffer by [RequestedBufferType::Buff].
    Written(usize),
    /// The user wants to know the requested data length to allocate the corresponding buffer in the future.
    DataLen(usize),
    /// Allocated buffer.
    ///
    /// The inner buffer is leaked and the user should free it using the `SCardFreeMemory` function.
    Allocated(&'data mut [u8]),
}

/// Represents the smart card status.
///
/// This structure is aimed to represent smart card status data on the FFI layer.
pub struct FfiScardStatus<'data> {
    /// List of display names (multi-string) by which the currently connected reader is known.
    pub readers: OutBuffer<'data>,
    /// Buffer that receives the ATR string from the currently inserted card, if available.
    ///
    /// [ATR string](https://learn.microsoft.com/en-us/windows/win32/secgloss/a-gly).
    pub atr: OutBuffer<'data>,
    /// Current state of the smart card in the reader.
    pub state: State,
    /// Current protocol, if any. The returned value is meaningful only if the returned value of pdwState is SCARD_SPECIFICMODE.
    pub protocol: Protocol,
}

/// Scard handle representation.
///
/// It also holds a pointer to the smart card context to which it belongs.
pub struct WinScardHandle {
    /// The emulated smart card.
    scard: Box<dyn WinScard>,
    /// Pointer to the smart card context to which it belongs.
    context: ScardContext,
}

impl WinScardHandle {
    /// Creates a new [WinSCardHandle] based on the provided data.
    pub fn new(scard: Box<dyn WinScard>, context: ScardContext) -> Self {
        Self { scard, context }
    }

    /// Returns the [WinScard] handle.
    pub fn scard(&self) -> &dyn WinScard {
        self.scard.as_ref()
    }

    /// Returns the mutable [WinScard] handle.
    pub fn scard_mut(&mut self) -> &mut dyn WinScard {
        self.scard.as_mut()
    }

    /// Returns the parent [ScardContext] it belongs.
    pub fn raw_context(&self) -> ScardContext {
        self.context
    }

    /// Returns mutable reference to the parent [WinScardContextHandle].
    pub fn context<'context>(&self) -> Option<&'context mut WinScardContextHandle> {
        unsafe { (self.raw_context() as *mut WinScardContextHandle).as_mut() }
    }

    /// Returns the requested smart card attribute.
    pub fn get_attribute(
        &self,
        attribute_id: AttributeId,
        buffer_type: RequestedBufferType,
    ) -> WinScardResult<OutBuffer> {
        let data = self.scard().get_attribute(attribute_id)?;

        self.context().unwrap().write_to_out_buf(data.as_ref(), buffer_type)
    }

    /// Returns smart card status.
    pub fn status(
        &mut self,
        readers_buf_type: RequestedBufferType,
        atr_but_type: RequestedBufferType,
    ) -> WinScardResult<FfiScardStatus> {
        let status = self.scard().status()?;
        let readers: Vec<_> = status.readers.into_iter().map(|r| r.to_string()).collect();
        let context = self.context().unwrap();

        let readers = context.write_multi_string(&readers, readers_buf_type)?;
        let atr = context.write_to_out_buf(status.atr.as_ref(), atr_but_type)?;

        Ok(FfiScardStatus {
            readers,
            atr,
            state: status.state,
            protocol: status.protocol,
        })
    }

    /// Returns smart card status but all strings are wide.
    pub fn status_wide(
        &mut self,
        readers_buf_type: RequestedBufferType,
        atr_but_type: RequestedBufferType,
    ) -> WinScardResult<FfiScardStatus> {
        let status = self.scard().status()?;
        let readers: Vec<_> = status.readers.into_iter().map(|r| r.to_string()).collect();
        let context = self.context().unwrap();

        let readers = context.write_multi_string_wide(&readers, readers_buf_type)?;
        let atr = context.write_to_out_buf(status.atr.as_ref(), atr_but_type)?;

        Ok(FfiScardStatus {
            readers,
            atr,
            state: status.state,
            protocol: status.protocol,
        })
    }
}

pub unsafe fn scard_handle_to_winscard<'a>(handle: ScardHandle) -> WinScardResult<&'a mut dyn WinScard> {
    if let Some(scard) = unsafe { (handle as *mut WinScardHandle).as_mut() } {
        Ok(scard.scard.as_mut())
    } else {
        Err(Error::new(
            ErrorKind::InvalidHandle,
            "Invalid smart card context handle.",
        ))
    }
}

pub unsafe fn scard_context_to_winscard_context<'a>(
    handle: ScardContext,
) -> WinScardResult<&'a mut dyn WinScardContext> {
    if let Some(context) = unsafe { (handle as *mut WinScardContextHandle).as_mut() } {
        Ok(context.scard_context.as_mut())
    } else {
        Err(Error::new(
            ErrorKind::InvalidHandle,
            "Invalid smart card context handle.",
        ))
    }
}

pub unsafe fn scard_io_request_to_io_request(pio_send_pci: LpScardIoRequest) -> WinScardResult<IoRequest> {
    let (cb_pci_length, dw_protocol) = unsafe { ((*pio_send_pci).cb_pci_length, (*pio_send_pci).dw_protocol) };
    // https://learn.microsoft.com/en-us/windows/win32/secauthn/scard-io-request
    //
    // Length, in bytes, of the SCARD_IO_REQUEST structure plus any following PCI-specific information.
    let pci_buf_len: usize = cb_pci_length.try_into()?;
    let buffer_len = pci_buf_len - size_of::<ScardIoRequest>();
    let buffer = unsafe { (pio_send_pci as *const u8).add(size_of::<ScardIoRequest>()) };

    Ok(IoRequest {
        protocol: Protocol::from_bits(dw_protocol).unwrap_or(Protocol::empty()),
        pci_info: unsafe { from_raw_parts(buffer, buffer_len) }.to_vec(),
    })
}

pub unsafe fn copy_io_request_to_scard_io_request(
    io_request: &IoRequest,
    scard_io_request: LpScardIoRequest,
) -> WinScardResult<()> {
    let pci_info_len = io_request.pci_info.len();
    let scard_pci_info_len = unsafe { (*scard_io_request).cb_pci_length }.try_into()?;

    if pci_info_len > scard_pci_info_len {
        return Err(Error::new(
            ErrorKind::InsufficientBuffer,
            format!(
                "ScardIoRequest::cb_pci_length is too small. Expected at least {} but got {}",
                pci_info_len, scard_pci_info_len
            ),
        ));
    }

    unsafe {
        (*scard_io_request).dw_protocol = io_request.protocol.bits();
        (*scard_io_request).cb_pci_length = pci_info_len.try_into()?;
    }

    let pci_buffer_ptr = unsafe { (scard_io_request as *mut u8).add(size_of::<ScardIoRequest>()) };
    let pci_buffer = unsafe { from_raw_parts_mut(pci_buffer_ptr, pci_info_len) };
    pci_buffer.copy_from_slice(&io_request.pci_info);

    Ok(())
}
