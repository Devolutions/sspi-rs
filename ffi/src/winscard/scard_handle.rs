use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{LpScardIoRequest, ScardContext, ScardHandle, ScardIoRequest};
use ffi_types::LpCVoid;
use winscard::winscard::{IoRequest, Protocol, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

/// Represents smart card context handle.
/// Additionally, it holds allocated buffers and created smart card handles.
/// We need them because during the smart card context deletion, we need to free all allcated resources.
pub struct WinScardContextHandle {
    /// Context of the emulated smart card.
    scard_context: Box<dyn WinScardContext>,
    /// Created smart card handles during the API usage.
    scards: Vec<ScardHandle>,
    /// Allocated buffers in out smart card context.
    /// All buffers are `[u8]`, so we need only pointer and don't need to remember its type.
    allocations: Vec<usize>,
}

impl WinScardContextHandle {
    pub fn with_scard_context(scard_context: Box<dyn WinScardContext>) -> Self {
        Self {
            scard_context,
            scards: Vec::new(),
            allocations: Vec::new(),
        }
    }

    pub fn scard_context(&self) -> &dyn WinScardContext {
        self.scard_context.as_ref()
    }

    pub fn add_scard(&mut self, scard: ScardHandle) -> WinScardResult<()> {
        if scard == 0 {
            return Err(Error::new(ErrorKind::InvalidHandle, "ScardHandle can not be NULL"));
        }

        self.scards.push(scard);

        Ok(())
    }

    pub fn remove_scard(&mut self, scard: ScardHandle) -> bool {
        if let Some(index) = self.scards.iter().position(|x| *x == scard) {
            self.scards.remove(index);

            true
        } else {
            false
        }
    }

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

    pub fn free_buffer(&mut self, buff: LpCVoid) -> bool {
        let buff = buff as usize;
        if !self.allocations.contains(&buff) {
            return false;
        }
        unsafe {
            libc::free(buff as _);
        }

        // safe: checked above
        let index = self.allocations.iter().position(|x| *x == buff).unwrap();
        self.allocations.remove(index);

        true
    }
}

impl Drop for WinScardContextHandle {
    fn drop(&mut self) {
        // [SCardReleaseContext](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreleasecontext)
        // ...freeing any resources allocated under that context, including SCARDHANDLE objects
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

/// Represents smart card handle.
/// It also holds a pointer to the smart card context to which it belongs.
pub struct WinScardHandle {
    /// The emulated smart card.
    scard: Box<dyn WinScard>,
    /// Pointer to the smart card context to which it belongs.
    context: ScardContext,
}

impl WinScardHandle {
    pub fn new(scard: Box<dyn WinScard>, context: ScardContext) -> Self {
        Self { scard, context }
    }

    pub fn scard(&self) -> &dyn WinScard {
        self.scard.as_ref()
    }

    pub fn context(&self) -> ScardContext {
        self.context
    }
}

pub fn scard_handle_to_winscard<'a>(handle: ScardHandle) -> WinScardResult<&'a mut dyn WinScard> {
    if let Some(scard) = unsafe { (handle as *mut WinScardHandle).as_mut() } {
        Ok(scard.scard.as_mut())
    } else {
        Err(Error::new(
            ErrorKind::InvalidHandle,
            "Invalid smart card context handle.",
        ))
    }
}

pub fn scard_context_to_winscard_context<'a>(handle: ScardContext) -> WinScardResult<&'a mut dyn WinScardContext> {
    if let Some(context) = unsafe { (handle as *mut WinScardContextHandle).as_mut() } {
        Ok(context.scard_context.as_mut())
    } else {
        Err(Error::new(
            ErrorKind::InvalidHandle,
            "Invalid smart card context handle.",
        ))
    }
}

pub unsafe fn scard_io_request_to_io_request(pio_send_pci: LpScardIoRequest) -> IoRequest {
    let buffer_len = (*pio_send_pci).cb_pci_length.try_into().unwrap();
    let buffer = (pio_send_pci as *const u8).add(size_of::<ScardIoRequest>());

    IoRequest {
        protocol: Protocol::from_bits((*pio_send_pci).dw_protocol).unwrap_or(Protocol::empty()),
        pci_info: from_raw_parts(buffer, buffer_len).to_vec(),
    }
}

pub unsafe fn copy_io_request_to_scard_io_request(
    io_request: &IoRequest,
    scard_io_request: LpScardIoRequest,
) -> WinScardResult<()> {
    let pci_info_len = io_request.pci_info.len();
    let scard_pci_info_len = (*scard_io_request).cb_pci_length.try_into().unwrap();

    if pci_info_len > scard_pci_info_len {
        return Err(Error::new(
            ErrorKind::InsufficientBuffer,
            format!(
                "ScardIoRequest::cb_pci_length is too small. Expected at least {} but got {}",
                pci_info_len, scard_pci_info_len
            ),
        ));
    }

    (*scard_io_request).dw_protocol = io_request.protocol.bits();
    (*scard_io_request).cb_pci_length = pci_info_len.try_into().unwrap();

    let pci_buffer_ptr = (scard_io_request as *mut u8).add(size_of::<ScardIoRequest>());
    let pci_buffer = from_raw_parts_mut(pci_buffer_ptr, pci_info_len);
    pci_buffer.copy_from_slice(&io_request.pci_info);

    Ok(())
}
