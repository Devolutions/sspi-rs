use std::slice::from_raw_parts_mut;

use ffi_types::{LpByte, LpDword, LpWStr};
use winscard::{Error, ErrorKind, WinScardResult};

use super::scard_handle::{OutBuffer, RequestedBufferType};

pub const SCARD_AUTOALLOCATE: u32 = 0xffffffff;

/// This function decides how to treat the provided buffer by the user and how to return the requested data.
///
/// When the user requests some data from the smart card using the WinSCard API, we have three ways
/// how to handle it:
/// * write data in the provided buffer.
/// * write data length of the requested data in the provided length pointer.
/// * allocate data by ourselves and write data pointer in the provided buffer.
#[instrument(level = "debug", ret)]
pub unsafe fn build_buf_request_type<'data>(
    p_buf: LpByte,
    pcb_buf: LpDword,
) -> WinScardResult<RequestedBufferType<'data>> {
    if pcb_buf.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "pcb_buf cannot be null"));
    }

    if p_buf.is_null() {
        // If this value is NULL, we ignore the buffer length, writes the length of the buffer that
        // would have been returned if this parameter had not been NULL, and returns a success code.
        return Ok(RequestedBufferType::Length);
    }
    // SAFETY: The `pcb_buf` parameter cannot be null. We've checked for it above.
    if unsafe { *pcb_buf } == SCARD_AUTOALLOCATE {
        // If the buffer length is specified as SCARD_AUTOALLOCATE, then data pointer is
        // converted to a pointer to a byte pointer, and receives the address of a block of memory
        // containing the attribute.
        Ok(RequestedBufferType::Allocate)
    } else {
        // SAFETY: `p_buf` and `pcb_buf` parameters can't be null. We've checked for it above.
        Ok(RequestedBufferType::Buf(unsafe {
            from_raw_parts_mut(p_buf, (*pcb_buf).try_into()?)
        }))
    }
}

/// This function behaves as the [build_buf_request_type] but here it expects a pointer
/// to the `u16` buffer instead of `u8`. So, the buffer length is multiplied by two.
#[instrument(level = "debug", ret)]
pub unsafe fn build_buf_request_type_wide<'data>(
    p_buf: LpWStr,
    pcb_buf: LpDword,
) -> WinScardResult<RequestedBufferType<'data>> {
    if pcb_buf.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "pcb_buf cannot be null"));
    }

    Ok(if p_buf.is_null() {
        // If this value is NULL, SCardGetAttrib ignores the buffer length supplied in pcbAttrLen,
        // writes the length of the buffer that would have been returned if this parameter had not been NULL
        // to pcbAttrLen, and returns a success code.
        RequestedBufferType::Length
    } else if
    // SAFETY: The `pcb_buf` parameter cannot be null. We've checked for it above.
    unsafe { *pcb_buf } == SCARD_AUTOALLOCATE {
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetattrib
        //
        // If the buffer length is specified as SCARD_AUTOALLOCATE, then pbAttr is converted to a pointer
        // to a byte pointer, and receives the address of a block of memory containing the attribute.
        RequestedBufferType::Allocate
    } else {
        // SAFETY: `p_buf` and `pcb_buf` parameters can't be null. We've checked for it above.
        RequestedBufferType::Buf(unsafe { from_raw_parts_mut(p_buf as *mut u8, usize::try_from(*pcb_buf)? * 2) })
    })
}

/// Saves the resulting data after the [RequestedBufferType] processing.
#[instrument(level = "debug", ret)]
pub unsafe fn save_out_buf(out_buf: OutBuffer, p_buf: LpByte, pcb_buf: LpDword) -> WinScardResult<()> {
    if pcb_buf.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "pcb_buf cannot be null"));
    }

    match out_buf {
        // SAFETY: We've checked for null above.
        OutBuffer::Written(len) => unsafe {
            // We already wrote the requested data in the provided buffer, so we only need to write the data length.
            *pcb_buf = len.try_into()?
        },
        // SAFETY: We've checked for null above.
        OutBuffer::DataLen(len) => unsafe {
            // The user requested only the requested data length, so we just return it.
            *pcb_buf = len.try_into()?
        },
        OutBuffer::Allocated(data) => {
            if p_buf.is_null() {
                return Err(Error::new(ErrorKind::InvalidParameter, "p_buf cannot be null"));
            }

            // SAFETY: We've checked for null above.
            unsafe {
                // We allocated a new memory for the requested data, so we need to save the buffer and buffer length.
                *(p_buf as *mut *mut u8) = data.as_mut_ptr();
                *pcb_buf = data.len().try_into()?;
            }
        }
    }

    Ok(())
}

/// This function behaves as the [save_out_buf] but here it expects a pointer
/// to the `u16` buffer instead of `u8`. So, the buffer length is divided by two.
#[instrument(level = "debug", ret)]
pub unsafe fn save_out_buf_wide(out_buf: OutBuffer, p_buf: LpWStr, pcb_buf: LpDword) -> WinScardResult<()> {
    if pcb_buf.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "pcb_buf cannot be null"));
    }

    match out_buf {
        // SAFETY: We've checked for null above.
        OutBuffer::Written(len) => unsafe { *pcb_buf = u32::try_from(len)? / 2 },
        // SAFETY: We've checked for null above.
        OutBuffer::DataLen(len) => unsafe { *pcb_buf = u32::try_from(len)? / 2 },
        OutBuffer::Allocated(data) => {
            if p_buf.is_null() {
                return Err(Error::new(ErrorKind::InvalidParameter, "p_buf cannot be null"));
            }

            // SAFETY: We've checked for null above.
            unsafe {
                *(p_buf as *mut *mut u8) = data.as_mut_ptr();
                *pcb_buf = u32::try_from(data.len())? / 2;
            }
        }
    }

    Ok(())
}
