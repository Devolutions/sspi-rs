use std::slice::from_raw_parts_mut;

use ffi_types::{LpByte, LpDword};
use winscard::{Error, ErrorKind, WinScardResult};

use crate::utils::vec_into_raw_ptr;

const SCARD_AUTOALLOCATE: u32 = 0xffffffff;

pub unsafe fn copy_buff(raw_buff: LpByte, raw_buff_len: LpDword, buff_to_copy: &[u8]) -> WinScardResult<()> {
    let buff_to_copy_len = buff_to_copy.len().try_into().unwrap();

    if raw_buff.is_null() {
        *raw_buff_len = buff_to_copy_len;
        return Ok(());
    }

    if *raw_buff_len == SCARD_AUTOALLOCATE {
        *raw_buff_len = buff_to_copy_len;
        // allocate a new buffer and write an address into raw_buff
        *(raw_buff as *mut *mut u8) = vec_into_raw_ptr(buff_to_copy.to_vec());
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
