use std::cell::RefCell;
use std::collections::HashMap;
use std::iter::once;
use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{LpScardIoRequest, ScardContext, ScardHandle, ScardIoRequest};
use ffi_types::{LpByte, LpDword, LpStr, LpWStr};
use winscard::winscard::{IoRequest, Protocol, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

use super::buff_alloc::SCARD_AUTOALLOCATE;
// use super::scard_context::CONTEXTS;
use crate::utils::vec_into_raw_ptr;
use crate::winscard::buff_alloc::copy_buff;

// thread_local! {
//     // Manages allocations required by the SCARD_AUTOALLOCATE. Data stored in this hashmap is used to free the memory once it's no longer needed
//     pub(crate) static ALLOCATIONS: RefCell<HashMap<usize, (*mut [()], AllocationType)>> = RefCell::new(HashMap::new());
// }

// pub enum AllocationType {
//     U8,
//     U16,
// }

pub fn scard_handle_to_winscard(handle: ScardHandle) -> *mut Box<dyn WinScard> {
    handle as *mut Box<dyn WinScard>
}

pub fn scard_context_to_winscard_context(handle: ScardContext) -> WinScardResult<*mut Box<dyn WinScardContext>> {
    // let ctx = CONTEXTS.lock().unwrap();

    // if ctx.contains(&handle) {
    Ok(handle as *mut Box<dyn WinScardContext>)
    // } else {
    //     Err(Error::new(
    //         ErrorKind::InvalidHandle,
    //         format!("Invalid ScardContext provided: {}", handle),
    //     ))
    // }
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

pub unsafe fn write_multistring_w(readers: &[&str], dest: LpWStr, dest_len: LpDword) -> WinScardResult<()> {
    let buffer: Vec<u16> = readers
        .iter()
        .flat_map(|reader| reader.encode_utf16().chain(once(0)))
        .chain(once(0))
        .collect();
    let buffer_len = buffer.len().try_into().unwrap();

    if *dest_len == SCARD_AUTOALLOCATE {
        *dest_len = buffer_len;
        // allocate a new buffer and write an address into raw_buff
        *(dest as *mut *mut u16) = vec_into_raw_ptr(buffer);
    } else {
        if buffer_len > *dest_len {
            return Err(Error::new(
                ErrorKind::InsufficientBuffer,
                format!("expected at least {} bytes but got {}.", buffer_len, *dest_len),
            ));
        }
        *dest_len = buffer_len;
        from_raw_parts_mut(dest, buffer.len()).copy_from_slice(buffer.as_slice());
    }

    Ok(())
}

pub unsafe fn write_multistring_a(readers: &[&str], dest: LpStr, dest_len: LpDword) -> WinScardResult<()> {
    let buffer: Vec<u8> = readers
        .iter()
        .flat_map(|reader| reader.as_bytes().iter().cloned().chain(once(0)))
        .chain(once(0))
        .collect();

    copy_buff(dest, dest_len, &buffer)
}
