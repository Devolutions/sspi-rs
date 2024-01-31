use std::cell::RefCell;
use std::collections::HashMap;
use std::iter::once;
use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{LpScardIoRequest, ScardContext, ScardHandle, ScardIoRequest};
use ffi_types::{LpDword, LpStr, LpWStr};
use winscard::winscard::{IoRequest, Protocol, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

// use super::scard_context::CONTEXTS;
use crate::utils::vec_into_raw_ptr;

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

pub unsafe fn null_terminated_lpwstr_to_string(p_str: LpWStr) -> String {
    let mut string_length = 0;
    loop {
        if *p_str.offset(string_length) != 0 {
            string_length += 1;
        } else {
            break;
        }
    }
    String::from_utf16_lossy(from_raw_parts_mut(p_str, string_length.try_into().unwrap()))
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

pub unsafe fn write_readers_w(readers: &[&str], dest: *mut LpWStr, dest_len: LpDword) -> WinScardResult<()> {
    let buffer: Vec<u16> = readers
        .iter()
        .flat_map(|reader| reader.encode_utf16().chain(once(0)))
        .chain(once(0))
        .collect();

    // let dest_str_len = (*dest_len).try_into().unwrap();
    // if buffer.len() > dest_str_len {
    //     return Err(Error::new(
    //         ErrorKind::InsufficientBuffer,
    //         format!(
    //             "Readers string buffer us too small. Expected at least {} but got {}",
    //             buffer.len(),
    //             dest_str_len
    //         ),
    //     ));
    // }

    let len = buffer.len();
    let buffer = vec_into_raw_ptr(buffer);

    // ALLOCATIONS.with(|map| {
    //     map.borrow_mut()
    //         .insert(ptr, (Box::into_raw(buffer) as *mut [()], AllocationType::U16))
    // });

    *dest = buffer;
    *dest_len = len.try_into().unwrap();

    Ok(())
}

pub unsafe fn write_readers_a(readers: &[&str], dest: LpStr, dest_len: LpDword) -> WinScardResult<()> {
    let buffer: Vec<u8> = readers
        .iter()
        .flat_map(|reader| reader.as_bytes().iter().cloned().chain(once(0)))
        .chain(once(0))
        .collect();

    let dest_str_len = (*dest_len).try_into().unwrap();
    if buffer.len() > dest_str_len {
        return Err(Error::new(
            ErrorKind::InsufficientBuffer,
            format!(
                "Readers string buffer us too small. Expected at least {} but got {}",
                buffer.len(),
                dest_str_len
            ),
        ));
    }

    let dest_buffer = from_raw_parts_mut(dest, buffer.len());
    dest_buffer.copy_from_slice(&buffer);

    Ok(())
}
