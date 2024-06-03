use std::iter::once;
use std::slice::from_raw_parts_mut;

use ffi_types::{LpByte, LpDword, LpStr, LpWStr};
use winscard::winscard::{OutBuffer, RequestedBufferType};
use winscard::{Error, ErrorKind, WinScardResult};

use super::scard_handle::WinScardContextHandle;
use crate::utils::str_to_w_buff;

pub const SCARD_AUTOALLOCATE: u32 = 0xffffffff;

pub unsafe fn copy_buff(
    context: &mut WinScardContextHandle,
    raw_buff: LpByte,
    raw_buff_len: LpDword,
    buff_to_copy: &[u8],
) -> WinScardResult<()> {
    let buff_to_copy_len = buff_to_copy.len().try_into()?;

    if raw_buff.is_null() {
        unsafe {
            *raw_buff_len = buff_to_copy_len;
        }
        return Ok(());
    }

    if unsafe { *raw_buff_len } == SCARD_AUTOALLOCATE {
        // Allocate a new buffer and write an address into raw_buff.
        let allocated = context.allocate_buffer(buff_to_copy.len())?;
        unsafe {
            *(raw_buff as *mut *mut u8) = allocated;
            *raw_buff_len = buff_to_copy_len;
            from_raw_parts_mut(allocated, buff_to_copy.len()).copy_from_slice(buff_to_copy);
        }
    } else {
        if buff_to_copy_len > unsafe { *raw_buff_len } {
            return Err(Error::new(
                ErrorKind::InsufficientBuffer,
                format!(
                    "expected at least {} bytes but got {}.",
                    buff_to_copy_len, *raw_buff_len
                ),
            ));
        }
        unsafe {
            *raw_buff_len = buff_to_copy_len;
            from_raw_parts_mut(raw_buff, buff_to_copy.len()).copy_from_slice(buff_to_copy);
        }
    }

    Ok(())
}

pub unsafe fn copy_w_buff(
    context: &mut WinScardContextHandle,
    raw_buf: LpWStr,
    raw_buf_len: LpDword,
    buff_to_copy: &[u16],
) -> WinScardResult<()> {
    let buff_to_copy_len = buff_to_copy.len().try_into()?;

    if raw_buf.is_null() {
        unsafe {
            *raw_buf_len = buff_to_copy_len;
        }
        return Ok(());
    }

    if unsafe { *raw_buf_len } == SCARD_AUTOALLOCATE {
        // Allocate a new buffer and write an address into raw_buff.
        let allocated = context.allocate_buffer(buff_to_copy.len() * 2)? as *mut u16;
        unsafe {
            *(raw_buf as *mut *mut u16) = allocated;
            *raw_buf_len = buff_to_copy_len;
            from_raw_parts_mut(allocated, buff_to_copy.len()).copy_from_slice(buff_to_copy);
        }
    } else {
        if buff_to_copy_len > unsafe { *raw_buf_len } {
            return Err(Error::new(
                ErrorKind::InsufficientBuffer,
                format!("expected at least {} bytes but got {}.", buff_to_copy_len, *raw_buf_len),
            ));
        }
        unsafe {
            *raw_buf_len = buff_to_copy_len;
            from_raw_parts_mut(raw_buf, buff_to_copy.len()).copy_from_slice(buff_to_copy);
        }
    }

    Ok(())
}

pub unsafe fn write_multistring_a(
    context: &mut WinScardContextHandle,
    strings: &[&str],
    dest: LpStr,
    dest_len: LpDword,
) -> WinScardResult<()> {
    let buffer: Vec<u8> = strings
        .iter()
        .flat_map(|reader| reader.as_bytes().iter().cloned().chain(once(0)))
        .chain(once(0))
        .collect();

    unsafe { copy_buff(context, dest, dest_len, &buffer) }
}

pub unsafe fn write_multistring_w(
    context: &mut WinScardContextHandle,
    strings: &[&str],
    dest: LpWStr,
    dest_len: LpDword,
) -> WinScardResult<()> {
    let buffer: Vec<u16> = strings
        .iter()
        .flat_map(|reader| str_to_w_buff(reader))
        .chain(once(0))
        .collect();

    unsafe { copy_w_buff(context, dest, dest_len, &buffer) }
}

// TODO: write proper comments.
pub unsafe fn build_buf_request_type<'data>(
    p_buf: LpByte,
    pcb_buf: LpDword,
) -> WinScardResult<RequestedBufferType<'data>> {
    Ok(if p_buf.is_null() {
        // If this value is NULL, SCardGetAttrib ignores the buffer length supplied in pcbAttrLen,
        // writes the length of the buffer that would have been returned if this parameter had not been NULL
        // to pcbAttrLen, and returns a success code.
        RequestedBufferType::Length
    } else if unsafe { *pcb_buf } == SCARD_AUTOALLOCATE {
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib
        //
        // If the buffer length is specified as SCARD_AUTOALLOCATE, then pbAttr is converted to a pointer
        // to a byte pointer, and receives the address of a block of memory containing the attribute.
        RequestedBufferType::Allocate
    } else {
        RequestedBufferType::Buff(unsafe { from_raw_parts_mut(p_buf, (*pcb_buf).try_into()?) })
    })
}

// TODO: write proper comments.
pub unsafe fn save_out_buf(
    context: &mut WinScardContextHandle,
    out_buf: OutBuffer,
    p_buf: LpByte,
    pcb_buf: LpDword,
) -> WinScardResult<()> {
    match out_buf {
        OutBuffer::Written(len) => unsafe { *pcb_buf = len.try_into()? },
        OutBuffer::DataLen(len) => unsafe { *pcb_buf = len.try_into()? },
        OutBuffer::Allocated(data) => {
            let allocated = context.allocate_buffer(data.len())?;

            let mut buf = unsafe { from_raw_parts_mut(allocated, data.len()) };
            buf.copy_from_slice(&data);

            unsafe {
                *(p_buf as *mut *mut u8) = allocated;
                *pcb_buf = data.len().try_into()?;
            }
        }
    }

    Ok(())
}
