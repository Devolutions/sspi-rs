use std::slice::from_raw_parts_mut;

use ffi_types::{LpByte, LpDword, LpWStr};
use winscard::WinScardResult;

use super::scard_handle::{OutBuffer, RequestedBufferType};

pub const SCARD_AUTOALLOCATE: u32 = 0xffffffff;

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

pub unsafe fn build_buf_request_type_wide<'data>(
    p_buf: LpWStr,
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
        RequestedBufferType::Buff(unsafe { from_raw_parts_mut(p_buf as *mut u8, usize::try_from(*pcb_buf)? * 2) })
    })
}

// TODO: write proper comments.
pub unsafe fn save_out_buf(out_buf: OutBuffer, p_buf: LpByte, pcb_buf: LpDword) -> WinScardResult<()> {
    match out_buf {
        OutBuffer::Written(len) => unsafe { *pcb_buf = len.try_into()? },
        OutBuffer::DataLen(len) => unsafe { *pcb_buf = len.try_into()? },
        OutBuffer::Allocated(data) => unsafe {
            *(p_buf as *mut *mut u8) = data.as_mut_ptr();
            *pcb_buf = data.len().try_into()?;
        },
    }

    Ok(())
}

pub unsafe fn save_out_buf_wide(out_buf: OutBuffer, p_buf: LpWStr, pcb_buf: LpDword) -> WinScardResult<()> {
    match out_buf {
        OutBuffer::Written(len) => unsafe { *pcb_buf = u32::try_from(len)? / 2 },
        OutBuffer::DataLen(len) => unsafe { *pcb_buf = u32::try_from(len)? / 2 },
        OutBuffer::Allocated(data) => unsafe {
            *(p_buf as *mut *mut u8) = data.as_mut_ptr();
            *pcb_buf = u32::try_from(data.len())? / 2;
        },
    }

    Ok(())
}
