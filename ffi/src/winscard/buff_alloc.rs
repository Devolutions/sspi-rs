use std::slice::from_raw_parts_mut;

use ffi_types::{LpByte, LpDword, LpWStr};
use winscard::{Error, ErrorKind, WinScardResult};

use super::scard_handle::WinScardContextHandle;

pub const SCARD_AUTOALLOCATE: u32 = 0xffffffff;

pub unsafe fn copy_buff(
    context: &mut WinScardContextHandle,
    raw_buff: LpByte,
    raw_buff_len: LpDword,
    buff_to_copy: &[u8],
) -> WinScardResult<()> {
    let buff_to_copy_len = buff_to_copy.len().try_into().unwrap();

    if raw_buff.is_null() {
        *raw_buff_len = buff_to_copy_len;
        return Ok(());
    }

    if *raw_buff_len == SCARD_AUTOALLOCATE {
        *raw_buff_len = buff_to_copy_len;
        // allocate a new buffer and write an address into raw_buff
        let allocated = context.allocate_buffer(buff_to_copy.len())?;
        *(raw_buff as *mut *mut u8) = allocated;
        from_raw_parts_mut(allocated, buff_to_copy.len()).copy_from_slice(buff_to_copy);
    } else {
        if buff_to_copy_len > *raw_buff_len {
            return Err(Error::new(
                ErrorKind::InsufficientBuffer,
                format!(
                    "expected at least {} bytes but got {}.",
                    buff_to_copy_len, *raw_buff_len
                ),
            ));
        }
        *raw_buff_len = buff_to_copy_len;
        from_raw_parts_mut(raw_buff, buff_to_copy.len()).copy_from_slice(buff_to_copy);
    }

    Ok(())
}

pub unsafe fn copy_w_buff(
    context: &mut WinScardContextHandle,
    raw_buff: LpWStr,
    raw_buff_len: LpDword,
    buff_to_copy: &[u16],
) -> WinScardResult<()> {
    let buff_to_copy_len = buff_to_copy.len().try_into().unwrap();

    if raw_buff.is_null() {
        *raw_buff_len = buff_to_copy_len;
        return Ok(());
    }

    if *raw_buff_len == SCARD_AUTOALLOCATE {
        *raw_buff_len = buff_to_copy_len;
        // allocate a new buffer and write an address into raw_buff
        let allocated = context.allocate_buffer(buff_to_copy.len() * 2)? as *mut u16;
        *(raw_buff as *mut *mut u16) = allocated;
        from_raw_parts_mut(allocated, buff_to_copy.len()).copy_from_slice(buff_to_copy);
    } else {
        if buff_to_copy_len > *raw_buff_len {
            return Err(Error::new(
                ErrorKind::InsufficientBuffer,
                format!(
                    "expected at least {} bytes but got {}.",
                    buff_to_copy_len, *raw_buff_len
                ),
            ));
        }
        *raw_buff_len = buff_to_copy_len;
        from_raw_parts_mut(raw_buff, buff_to_copy.len()).copy_from_slice(buff_to_copy);
    }

    Ok(())
}
