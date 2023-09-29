use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{LpScardIoRequest, ScardContext, ScardHandle, ScardIoRequest};
use winscard::winscard::{IoRequest, Protocol, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

pub fn scard_handle_to_winscard(handle: ScardHandle) -> *mut Box<dyn WinScard> {
    handle as *mut Box<dyn WinScard>
}
pub fn scard_context_to_winscard_context(handle: ScardContext) -> *mut Box<dyn WinScardContext> {
    handle as *mut Box<dyn WinScardContext>
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
